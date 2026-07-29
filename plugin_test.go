package sokol_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "local-plugin-token-with-at-least-thirty-two-characters"

type agentFixture struct {
	server   *httptest.Server
	requests atomic.Int64
	inputs   chan evaluationRequest
	handler  atomic.Value
}

type agentHandler func(http.ResponseWriter, *http.Request, evaluationRequest)

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	fixture := &agentFixture{inputs: make(chan evaluationRequest, 32)}
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
		writeAgentResponse(writer, evaluationResponse{
			Decision: "allow", Status: 200, RequestID: input.RequestID,
			PublicReason: "request_allowed", CacheTTLMS: 0,
		})
	}))
	fixture.server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		fixture.requests.Add(1)
		if request.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		var input evaluationRequest
		decoder := json.NewDecoder(request.Body)
		if err := decoder.Decode(&input); err != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		fixture.inputs <- input
		fixture.handler.Load().(agentHandler)(writer, request, input)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func writeAgentResponse(writer http.ResponseWriter, response evaluationResponse) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(response)
}

func testConfig(t *testing.T, fixture *agentFixture) *Config {
	t.Helper()
	directory := t.TempDir()
	tokenFile := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := CreateConfig()
	config.Agent.Endpoint = fixture.server.URL
	config.Agent.TokenFile = tokenFile
	config.Agent.ConnectTimeout = "20ms"
	config.Agent.RequestTimeout = "100ms"
	config.Responses.Root = directory
	config.Responses.ReloadInterval = "1s"
	config.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
	return config
}

func newMiddleware(t *testing.T, config *Config, next http.Handler) http.Handler {
	t.Helper()
	handler, err := New(context.Background(), next, config, "test-sokol")
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestAllowCallsNextAndSendsBoundedNormalizedMetadata(t *testing.T) {
	fixture := newAgentFixture(t)
	var downstream atomic.Int64
	handler := newMiddleware(t, testConfig(t, fixture), http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		downstream.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest("GET", "https://example.test/api/items?page=1", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.8")
	request.Header.Set("User-Agent", "compat-test")
	request.Header.Set("Authorization", "must-not-be-forwarded")
	request.AddCookie(&http.Cookie{Name: "__Host-sokol_trust", Value: "trust"})
	request.AddCookie(&http.Cookie{Name: "session", Value: "must-not-be-forwarded"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || downstream.Load() != 1 {
		t.Fatalf("status=%d downstream=%d", response.Code, downstream.Load())
	}
	input := <-fixture.inputs
	if input.ClientIP != "203.0.113.8" || input.Host != "example.test" ||
		input.Path != "/api/items" || input.Query != "page=1" ||
		input.ProtocolType != "http" || input.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("unexpected input: %#v", input)
	}
	if input.Headers["user-agent"] != "compat-test" {
		t.Fatalf("selected headers = %#v", input.Headers)
	}
	if _, present := input.Headers["authorization"]; present {
		t.Fatal("authorization header was forwarded")
	}
	if _, present := input.Headers["content-length"]; present {
		t.Fatal("content length was invented for GET")
	}
	if input.Cookies["__Host-sokol_trust"] != "trust" || input.Cookies["session"] != "" {
		t.Fatalf("selected cookies = %#v", input.Cookies)
	}
}

func TestBlockRendersCustomHTMLWithEscapedPlaceholdersAndSecurityHeaders(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
		writeAgentResponse(writer, evaluationResponse{
			Decision: "block", Status: 403, RequestID: input.RequestID,
			PublicReason: "request_blocked", CacheTTLMS: 0,
		})
	}))
	config := testConfig(t, fixture)
	page := `<h1>{{SOKOL_HOST}}</h1><p>{{SOKOL_PATH}}</p><code>{{SOKOL_REQUEST_ID}}</code>`
	if err := os.WriteFile(filepath.Join(config.Responses.Root, config.Responses.BlockFile), []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("blocked request reached downstream")
	}))
	request := httptest.NewRequest("GET", "http://example.test/a%3Cscript%3E", nil)
	request.RemoteAddr = "198.51.100.2:1234"
	request.Host = `<img src=x onerror=alert(1)>`
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "<img") || strings.Contains(response.Body.String(), "<script>") {
		t.Fatalf("request-derived HTML was not escaped: %s", response.Body.String())
	}
	for name, expected := range map[string]string{
		"Cache-Control":          "no-store, private",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"X-Robots-Tag":           "noindex, nofollow, noarchive",
	} {
		if got := response.Header().Get(name); got != expected {
			t.Fatalf("%s = %q", name, got)
		}
	}
	csp := response.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing CSP")
	}
	for _, expected := range []string{
		"style-src 'unsafe-inline' https://fonts.bunny.net",
		"font-src https://fonts.bunny.net",
	} {
		if !strings.Contains(csp, expected) {
			t.Fatalf("CSP does not permit the pinned Bunny Fonts origin: %q", csp)
		}
	}
	if strings.Contains(csp, "*") {
		t.Fatalf("CSP contains a wildcard source: %q", csp)
	}
}

func TestJSONEnforcementResponseDoesNotLeakAgentInternals(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
		writeAgentResponse(writer, evaluationResponse{
			Decision: "rate_limit", Status: 429, RequestID: input.RequestID,
			PublicReason: "rate_limited", CacheTTLMS: 0, ResourceID: "private-resource",
		})
	}))
	handler := newMiddleware(t, testConfig(t, fixture), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("rate-limited request reached downstream")
	}))
	request := httptest.NewRequest("GET", "http://api.example.test/items", nil)
	request.RemoteAddr = "198.51.100.2:1234"
	request.Header.Set("Accept", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), "private-resource") {
		t.Fatalf("response leaked resource: %s", response.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) != 4 || payload["public_reason"] != "rate_limited" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestContentNegotiationHonorsQualityValues(t *testing.T) {
	if prefersJSON("application/json;q=0.1, text/html;q=0.9", "json") {
		t.Fatal("lower-quality JSON was preferred")
	}
	if !prefersJSON("text/html;q=0.1, application/json;q=0.9", "html") {
		t.Fatal("higher-quality JSON was not preferred")
	}
	if prefersJSON("application/json;q=0, text/html;q=1", "json") {
		t.Fatal("explicitly unacceptable JSON was preferred")
	}
}

func TestMissingAndOversizedCustomPagesUseFallback(t *testing.T) {
	for _, test := range []struct {
		name      string
		writePage bool
	}{
		{name: "missing"},
		{name: "oversized", writePage: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentFixture(t)
			fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
				writeAgentResponse(writer, evaluationResponse{
					Decision: "block", Status: 403, RequestID: input.RequestID,
					PublicReason: "request_blocked",
				})
			}))
			config := testConfig(t, fixture)
			config.Responses.MaximumFileBytes = 32
			if test.writePage {
				if err := os.WriteFile(
					filepath.Join(config.Responses.Root, config.Responses.BlockFile),
					bytes.Repeat([]byte("x"), 33), 0o600,
				); err != nil {
					t.Fatal(err)
				}
			}
			handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.RemoteAddr = "198.51.100.2:1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !strings.Contains(response.Body.String(), "Request unavailable") {
				t.Fatalf("fallback not rendered: %s", response.Body.String())
			}
		})
	}
}

func TestAgentTimeoutIsBoundedAndCircuitBreakerAvoidsStorm(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, _ evaluationRequest) {
		time.Sleep(200 * time.Millisecond)
		writer.Header().Set("Content-Type", "application/json")
	}))
	config := testConfig(t, fixture)
	config.Agent.RequestTimeout = "20ms"
	config.CircuitBreaker.FailureThreshold = 2
	var downstream atomic.Int64
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		downstream.Add(1)
	}))
	start := time.Now()
	for index := 0; index < 6; index++ {
		request := httptest.NewRequest("GET", "http://example.test/", nil)
		request.RemoteAddr = "198.51.100.2:1234"
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	if elapsed := time.Since(start); elapsed > 150*time.Millisecond {
		t.Fatalf("timeouts were not bounded: %s", elapsed)
	}
	if fixture.requests.Load() != 2 || downstream.Load() != 6 {
		t.Fatalf("agent requests=%d downstream=%d", fixture.requests.Load(), downstream.Load())
	}
}

func TestMalformedAgentResponseUsesIndependentFailureMode(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, _ evaluationRequest) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"decision":"block","unknown":true}`)
	}))
	config := testConfig(t, fixture)
	config.FailureMode.AgentUnavailable = "allow"
	config.FailureMode.MalformedResponse = "deny"
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed fail-closed request reached downstream")
	}))
	request := httptest.NewRequest("GET", "http://example.test/", nil)
	request.RemoteAddr = "198.51.100.2:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestCachedDenyRemainsEffectiveDuringAgentFailure(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
		writeAgentResponse(writer, evaluationResponse{
			Decision: "block", Status: 403, RequestID: input.RequestID,
			PublicReason: "request_blocked", CacheTTLMS: 1000,
		})
	}))
	config := testConfig(t, fixture)
	config.Cache.MaximumTTL = "1s"
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("cached deny reached downstream")
	}))
	for index := 0; index < 2; index++ {
		request := httptest.NewRequest("GET", "http://example.test/", nil)
		request.RemoteAddr = "198.51.100.2:1234"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status = %d", response.Code)
		}
	}
	if fixture.requests.Load() != 1 {
		t.Fatalf("agent requests = %d", fixture.requests.Load())
	}
}

func TestEnabledBodyCaptureRestoresBodyForDownstream(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.RequestBody.Enabled = true
	config.RequestBody.MaximumBytes = 1024
	original := []byte(`{"upload":"value"}`)
	var downstreamBody []byte
	handler := newMiddleware(t, config, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		downstreamBody, _ = io.ReadAll(request.Body)
	}))
	request := httptest.NewRequest("POST", "http://example.test/api", bytes.NewReader(original))
	request.RemoteAddr = "198.51.100.2:1234"
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	input := <-fixture.inputs
	if !bytes.Equal(input.Body, original) || !bytes.Equal(downstreamBody, original) {
		t.Fatalf("agent body=%q downstream body=%q", input.Body, downstreamBody)
	}
}

func TestOversizedCapturedBodySignalsTruncationAndRestoresDownstream(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.RequestBody.Enabled = true
	config.RequestBody.MaximumBytes = 32
	config.RequestBody.OversizeAction = "headers_only"
	original := bytes.Repeat([]byte("x"), 128)
	var downstreamBody []byte
	handler := newMiddleware(t, config, http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		downstreamBody, _ = io.ReadAll(request.Body)
	}))
	request := httptest.NewRequest("POST", "http://example.test/api", bytes.NewReader(original))
	request.RemoteAddr = "198.51.100.2:1234"
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	input := <-fixture.inputs
	if len(input.Body) != 0 || !input.BodyTruncated || !bytes.Equal(downstreamBody, original) {
		t.Fatalf("agent body=%d truncated=%t downstream body=%d", len(input.Body), input.BodyTruncated, len(downstreamBody))
	}
}
