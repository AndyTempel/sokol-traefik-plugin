package sokol_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
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
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	handler, err := New(ctx, next, config, "test-sokol")
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
		"style-src 'unsafe-inline' https://sokol-static.my-k.cloud",
		"font-src https://sokol-static.my-k.cloud",
	} {
		if !strings.Contains(csp, expected) {
			t.Fatalf("CSP does not permit the pinned Bunny Fonts origin: %q", csp)
		}
	}
	if strings.Contains(csp, "*") {
		t.Fatalf("CSP contains a wildcard source: %q", csp)
	}
}

func TestLocalChallengeBrowserFlowSetsHardenedTrustCookie(t *testing.T) {
	token := strings.Repeat("challenge-state-", 8)
	var createInput challengeCreateRequest
	var verifyInput challengeVerifyRequest
	var verifyRequestID string
	var downstream atomic.Int64
	agentServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/evaluate":
			var input evaluationRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Error(err)
				return
			}
			if input.Cookies["__Host-sokol_trust"] == "signed-local-trust" {
				writeAgentResponse(writer, evaluationResponse{
					Decision: "allow", Status: 200, RequestID: input.RequestID,
					PublicReason: "request_allowed",
				})
				return
			}
			writeAgentResponse(writer, evaluationResponse{
				Decision: "challenge", Status: 403, RequestID: input.RequestID,
				PublicReason: "challenge_required", ResourceID: "resource-1",
				SiteID: "site-1", ChallengeURL: "/.sokol/challenge",
				ChallengeToken: token, ChallengeAutoStart: true,
			})
		case "/v1/challenge/create":
			if err := json.NewDecoder(request.Body).Decode(&createInput); err != nil {
				t.Error(err)
				return
			}
			_ = json.NewEncoder(writer).Encode(map[string]any{
				"algorithm":  "PBKDF2/SHA-256",
				"parameters": map[string]any{"salt": "test", "challenge": "test"},
				"signature":  "test",
			})
		case "/v1/challenge/verify":
			verifyRequestID = request.Header.Get("X-Request-ID")
			if err := json.NewDecoder(request.Body).Decode(&verifyInput); err != nil {
				t.Error(err)
				return
			}
			time.Sleep(50 * time.Millisecond)
			_ = json.NewEncoder(writer).Encode(challengeVerifyResponse{
				Verified: true, PublicReason: "challenge_verified",
				CookieName:  "__Host-sokol_trust",
				CookieValue: "signed-local-trust", CookieMaxAge: 3600,
			})
		default:
			http.Error(writer, "unexpected path", http.StatusNotFound)
		}
	}))
	defer agentServer.Close()

	config := testConfig(t, &agentFixture{server: agentServer})
	config.Agent.RequestTimeout = "20ms"
	config.Challenge.RequestTimeout = "500ms"
	pluginRoot, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	config.Responses.Root = pluginRoot
	config.Responses.ChallengeFile = "pages/challenge.html"
	handler := newMiddleware(t, config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		downstream.Add(1)
		if !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
			t.Error("allowed request did not preserve WebSocket upgrade")
		}
		writer.WriteHeader(http.StatusSwitchingProtocols)
	}))

	pageRequest := httptest.NewRequest("GET", "https://example.test/private", nil)
	pageRequest.RemoteAddr = "198.51.100.7:1234"
	pageRequest.Header.Set("Accept", "text/html")
	pageResponse := httptest.NewRecorder()
	handler.ServeHTTP(pageResponse, pageRequest)
	if pageResponse.Code != http.StatusForbidden ||
		!strings.Contains(pageResponse.Body.String(), `data-auto-start="true"`) ||
		strings.Contains(pageResponse.Body.String(), "{{SOKOL_") {
		t.Fatalf("challenge page was not fully rendered: status=%d", pageResponse.Code)
	}
	csp := pageResponse.Header().Get("Content-Security-Policy")
	for _, origin := range []string{
		"https://sokol-static.my-k.cloud",
		"https://sokol.my-k.cloud",
		"https://sokol-static.my-k.cloud",
		"'wasm-unsafe-eval'",
	} {
		if !strings.Contains(csp, origin) {
			t.Fatalf("challenge CSP is missing %s: %s", origin, csp)
		}
	}
	if strings.Contains(csp, " 'unsafe-eval'") {
		t.Fatalf("challenge CSP permits broad script evaluation: %s", csp)
	}
	if strings.Contains(pageResponse.Body.String(), `id="start"`) ||
		strings.Contains(pageResponse.Body.String(), "Start verification") {
		t.Fatal("challenge page rendered a duplicate verification button")
	}
	for _, eventName := range []string{"verified", "statechange"} {
		if !strings.Contains(pageResponse.Body.String(), eventName) {
			t.Fatalf("challenge page does not handle %s completion", eventName)
		}
	}

	createURL := "https://example.test/.sokol/challenge?token=" +
		url.QueryEscape(token) +
		"&resource=resource-1&site=site-1&path=%2Fprivate"
	createRequest := httptest.NewRequest("GET", createURL, nil)
	createRequest.RemoteAddr = "198.51.100.7:1234"
	createRequest.Header.Set("User-Agent", "browser-test")
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusOK ||
		createInput.Context.ClientIP != "198.51.100.7" ||
		createInput.Context.ResourceID != "resource-1" {
		t.Fatalf("challenge create failed: status=%d input=%#v", createResponse.Code, createInput)
	}

	verifyBody := `{"challenge_token":` + strconv.Quote(token) +
		`,"resource_id":"resource-1","site_id":"site-1","path":"/private","payload":"base64-payload"}`
	verifyRequest := httptest.NewRequest(
		"POST",
		"https://example.test/.sokol/challenge/verify",
		strings.NewReader(verifyBody),
	)
	verifyRequest.RemoteAddr = "198.51.100.7:1234"
	verifyRequest.Header.Set("Origin", "https://example.test")
	verifyRequest.Header.Set("Content-Type", "application/json")
	verifyResponse := httptest.NewRecorder()
	handler.ServeHTTP(verifyResponse, verifyRequest)
	if verifyResponse.Code != http.StatusOK ||
		verifyInput.Context.ClientIP != "198.51.100.7" ||
		verifyRequestID == "" {
		t.Fatalf("challenge verify failed: status=%d input=%#v", verifyResponse.Code, verifyInput)
	}
	cookies := verifyResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-sokol_trust" ||
		!cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteLaxMode ||
		cookies[0].Path != "/" || cookies[0].MaxAge != 3600 {
		t.Fatalf("trust cookie attributes = %#v", cookies)
	}

	websocketRequest := httptest.NewRequest("GET", "https://example.test/socket", nil)
	websocketRequest.RemoteAddr = "198.51.100.7:1234"
	websocketRequest.Header.Set("Connection", "Upgrade")
	websocketRequest.Header.Set("Upgrade", "websocket")
	websocketRequest.AddCookie(cookies[0])
	websocketResponse := httptest.NewRecorder()
	handler.ServeHTTP(websocketResponse, websocketRequest)
	if websocketResponse.Code != http.StatusSwitchingProtocols ||
		downstream.Load() != 1 {
		t.Fatalf(
			"trusted WebSocket was not preserved: status=%d downstream=%d",
			websocketResponse.Code,
			downstream.Load(),
		)
	}
}

func TestChallengeSubmissionRejectsCrossOriginAndOversizedBodies(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.Challenge.MaximumBodyBytes = 1024
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	for _, test := range []struct {
		name   string
		origin string
		body   string
		status int
	}{
		{
			name: "cross-origin", origin: "https://evil.example",
			body:   `{"challenge_token":"` + strings.Repeat("x", 32) + `","resource_id":"r","site_id":"s","path":"/","payload":"x"}`,
			status: http.StatusForbidden,
		},
		{
			name: "oversized", origin: "https://example.test",
			body: `{"challenge_token":"` + strings.Repeat("x", 32) +
				`","resource_id":"r","site_id":"s","path":"/","payload":"` +
				strings.Repeat("x", 1025) + `"}`,
			status: http.StatusRequestEntityTooLarge,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				"POST",
				"https://example.test/.sokol/challenge/verify",
				strings.NewReader(test.body),
			)
			request.RemoteAddr = "198.51.100.7:1234"
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.status, response.Body.String())
			}
		})
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

func TestMissingOversizedAndInvalidUTF8CustomPagesUseFallback(t *testing.T) {
	for _, test := range []struct {
		name string
		page []byte
	}{
		{name: "missing"},
		{name: "oversized", page: bytes.Repeat([]byte("x"), 33)},
		{name: "invalid-utf8", page: []byte{0xff, 0xfe}},
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
			if test.page != nil {
				if err := os.WriteFile(
					filepath.Join(config.Responses.Root, config.Responses.BlockFile),
					test.page, 0o600,
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
			Cacheable: true, CacheKey: strings.Repeat("a", 64),
			CacheKeyScope: "request", DecisionScope: "resource:private-resource",
			PolicyRevision: 1, ResourceID: "private-resource",
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

func TestWAFAllowCannotPrimeCacheForLaterMaliciousRequest(t *testing.T) {
	fixture := newAgentFixture(t)
	fixture.handler.Store(agentHandler(func(writer http.ResponseWriter, _ *http.Request, input evaluationRequest) {
		response := evaluationResponse{
			Decision: "allow", Status: 200, RequestID: input.RequestID,
			PublicReason: "request_allowed",
		}
		if bytes.Contains(input.Body, []byte("UNION SELECT")) {
			response.Decision = "block"
			response.Status = http.StatusForbidden
			response.PublicReason = "waf_blocked"
		}
		writeAgentResponse(writer, response)
	}))
	config := testConfig(t, fixture)
	config.RequestBody.Enabled = true
	config.RequestBody.MaximumBytes = 1024
	var downstream atomic.Int64
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		downstream.Add(1)
	}))

	for _, body := range []string{
		`{"query":"harmless"}`,
		`{"query":"1 UNION SELECT password FROM users"}`,
	} {
		request := httptest.NewRequest("POST", "http://example.test/search", strings.NewReader(body))
		request.RemoteAddr = "198.51.100.2:1234"
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
	}
	if fixture.requests.Load() != 2 {
		t.Fatalf("agent requests = %d, harmless allow primed cache", fixture.requests.Load())
	}
	if downstream.Load() != 1 {
		t.Fatalf("downstream requests = %d", downstream.Load())
	}
}

func TestCacheRequiresAgentAuthorizationAndNeverStoresChallengeTokens(t *testing.T) {
	cache := newDecisionCache(8, time.Second)
	request := evaluationRequest{
		RequestID: "one", ClientIP: "192.0.2.1", Method: "GET",
		Scheme: "https", Host: "example.test", Path: "/", ProtocolType: "http",
	}
	now := time.Now()
	cache.put(request, evaluationResponse{
		Decision: "block", Status: 403, RequestID: "one",
		PublicReason: "request_blocked", CacheTTLMS: 1000,
	}, now)
	if _, ok := cache.get(request, "two", now); ok {
		t.Fatal("non-authorized response was cached")
	}
	cache.put(request, evaluationResponse{
		Decision: "challenge", Status: 403, RequestID: "one",
		PublicReason: "challenge_required", CacheTTLMS: 1000,
		Cacheable: true, CacheKey: strings.Repeat("a", 64),
		CacheKeyScope: "request", DecisionScope: "resource:r",
		PolicyRevision: 1, ResourceID: "r", ChallengeToken: "secret",
	}, now)
	if _, ok := cache.get(request, "two", now); ok {
		t.Fatal("challenge token was cached")
	}
}

func TestCacheRequiresAgentAuthorizationAndExactRequestBinding(t *testing.T) {
	cache := newDecisionCache(16, time.Second)
	base := evaluationRequest{
		RequestID: "one", ClientIP: "192.0.2.1", Method: "POST",
		Scheme: "https", Host: "example.test", Path: "/api/items",
		Query: "page=1", ProtocolType: "http", HTTPVersion: "1.1",
		Headers: map[string]string{"Authorization": "Bearer one"},
		Cookies: map[string]string{"session": "one"},
		Body:    []byte(`{"value":"one"}`),
	}
	cache.put(base, evaluationResponse{
		Decision: "block", Status: 403, RequestID: "one",
		PublicReason: "request_blocked", CacheTTLMS: 1000,
		Cacheable: true, CacheKey: strings.Repeat("a", 64),
		CacheKeyScope: "request", DecisionScope: "resource:r",
		PolicyRevision: 7, ResourceID: "r",
	}, time.Now())

	mutations := []evaluationRequest{
		base,
		base,
		base,
		base,
		base,
	}
	mutations[0].Path = "/api/admin"
	mutations[1].Query = "page=2"
	mutations[2].Headers = map[string]string{"Authorization": "Bearer two"}
	mutations[3].Cookies = map[string]string{"session": "two"}
	mutations[4].Body = []byte(`{"value":"two"}`)
	for index, changed := range mutations {
		if _, ok := cache.get(changed, "changed", time.Now()); ok {
			t.Fatalf("mutation %d reused a differently bound decision", index)
		}
	}
	if _, ok := cache.get(base, "two", time.Now()); !ok {
		t.Fatal("exact request did not reuse its authorized decision")
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
