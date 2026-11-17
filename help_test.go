package sokol_traefik_plugin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHelpDestinationsAndFallbackRendering(t *testing.T) {
	for _, tc := range []struct{ decision, reason, destination string }{
		{"block", "request_blocked", "block?type=policy"},
		{"block", "waf_blocked", "block?type=firewall"},
		{"block", "bad_actor_drop", "block?type=reputation"},
		{"block", "bad_actor_challenge_unavailable", "block?type=reputation"},
		{"block", "behavioral_block", "block?type=behavior"},
		{"error", "request_body_too_large", "block?type=request"},
		{"block", "rate_limit_block", "rate-limit?type=rate-limit"},
		{"rate_limit", "rate_limit_exceeded", "rate-limit?type=rate-limit"},
		{"rate_limit", "behavioral_rate_limit", "rate-limit?type=rate-limit"},
		{"challenge", "rate_limit_challenge", "challenge?type=rate-limit"},
		{"challenge", "behavioral_challenge", "challenge?type=behavior"},
		{"challenge", "bad_actor_challenge", "challenge?type=reputation"},
		{"challenge", "challenge_required", "challenge?type=policy"},
		{"error", "challenge_unavailable", "unavailable?type=unavailable"},
		{"error", "backend_unavailable", "unavailable?type=unavailable"},
		{"block", `unknown"><script>alert(1)</script>`, "block?type=policy"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			config := CreateConfig().Responses
			store := newPageStore(config, t.TempDir(), time.Second)
			req := httptest.NewRequest("GET", "https://private.example/secret?token=private-token", nil)
			req.Header.Set("Accept", "text/html")
			response := evaluationResponse{Decision: tc.decision, Status: 503, RequestID: "id-123", PublicReason: tc.reason, RetryAfterSeconds: 30}
			writer := httptest.NewRecorder()
			store.write(writer, req, response)
			body := writer.Body.String()
			destination := "https://sokol.my-k.cloud/help/" + tc.destination
			if !strings.Contains(body, `href="`+destination+`"`) || !strings.Contains(body, "id-123") || !strings.Contains(body, "website owner first") {
				t.Fatalf("missing help in fallback: %s", body)
			}
			if strings.Contains(body, "{{SOKOL_") || strings.Contains(body, "private-token") || strings.Contains(body, "private.example") || strings.Contains(body, tc.reason) {
				t.Fatalf("unresolved or unsafe fallback: %s", body)
			}
			if !strings.Contains(body, "Wait at least 30 seconds") {
				t.Fatal("missing retry guidance")
			}
			if tc.decision == "rate_limit" || tc.decision == "block" {
				if writer.Header().Get("Retry-After") != "30" {
					t.Fatal("lost retry header")
				}
			}
		})
	}
}

func TestShippedPagesRenderHelpWithoutUnresolvedPlaceholders(t *testing.T) {
	for _, decision := range []string{"block", "rate_limit", "challenge", "error"} {
		config := CreateConfig().Responses
		store := newPageStore(config, "pages", time.Second)
		req := httptest.NewRequest("GET", "https://example.test/", nil)
		req.Header.Set("Accept", "text/html")
		writer := httptest.NewRecorder()
		store.write(writer, req, evaluationResponse{Decision: decision, PublicReason: "request_blocked", RequestID: "test-request"})
		body := writer.Body.String()
		if strings.Contains(body, "{{SOKOL_") || !strings.Contains(body, `href="https://sokol.my-k.cloud/help/`) || !strings.Contains(body, "test-request") || strings.Contains(body, "request_blocked") {
			t.Fatalf("invalid shipped %s page: %s", decision, body)
		}
	}
}

func TestRejectedRequestsRenderRequestHelp(t *testing.T) {
	config := testConfig(t, newAgentFixture(t))
	config.RequestBody.Enabled = true
	config.RequestBody.MaximumBytes = 32
	config.RequestBody.OversizeAction = "reject"
	page, err := os.ReadFile(filepath.Join("pages", config.Responses.UnavailableFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.Responses.Root, config.Responses.UnavailableFile), page, 0600); err != nil {
		t.Fatal(err)
	}
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("rejected request reached upstream")
	}))

	for _, test := range []struct {
		path    string
		body    string
		status  int
		message string
	}{
		{"/../form", "", 400, "couldn’t read the request as sent"},
		{"/form", strings.Repeat("x", 128), 413, "exceeded this website’s size limit"},
	} {
		req := httptest.NewRequest("POST", "https://example.test"+test.path, strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		body := rec.Body.String()
		if rec.Code != test.status || !strings.Contains(body, "https://sokol.my-k.cloud/help/block?type=request") ||
			!strings.Contains(body, test.message) || strings.Contains(body, "Protection unavailable") {
			t.Fatalf("unexpected rejection for %s: %d %s", test.path, rec.Code, body)
		}
	}
}
