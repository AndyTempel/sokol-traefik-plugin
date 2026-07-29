package sokol_traefik_plugin

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
)

func TestBodyCaptureRestoresExactDownstreamBytes(t *testing.T) {
	original := []byte(`{"hello":"world"}`)
	request := httptest.NewRequest("POST", "http://example.test/api", bytes.NewReader(original))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	captured, oversized, err := captureRequestBody(request, RequestBodyConfig{
		Enabled: true, MaximumBytes: 1024, ContentTypes: []string{"application/json"},
	}, "http")
	if err != nil {
		t.Fatal(err)
	}
	if oversized || !bytes.Equal(captured, original) {
		t.Fatalf("captured=%q oversized=%v", captured, oversized)
	}
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored body = %q", restored)
	}
}

func TestBodyCaptureReadsOnlyLimitPlusOneAndRestoresOversize(t *testing.T) {
	original := bytes.Repeat([]byte("x"), 128)
	request := httptest.NewRequest("POST", "http://example.test/api", bytes.NewReader(original))
	request.Header.Set("Content-Type", "application/json")
	captured, oversized, err := captureRequestBody(request, RequestBodyConfig{
		Enabled: true, MaximumBytes: 32, ContentTypes: []string{"application/json"},
	}, "http")
	if err != nil {
		t.Fatal(err)
	}
	if !oversized || captured != nil {
		t.Fatalf("captured=%q oversized=%v", captured, oversized)
	}
	restored, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored body length = %d", len(restored))
	}
}

func TestBodyCaptureBypassesStreamingProtocolsAndConfiguredPaths(t *testing.T) {
	for _, test := range []struct {
		name     string
		protocol string
		path     string
	}{
		{name: "websocket", protocol: "websocket", path: "/api"},
		{name: "grpc", protocol: "grpc", path: "/api"},
		{name: "sse", protocol: "sse", path: "/api"},
		{name: "webdav", protocol: "webdav", path: "/api"},
		{name: "stream", protocol: "stream", path: "/api"},
		{name: "configured upload", protocol: "http", path: "/uploads/large"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "http://example.test"+test.path, bytes.NewReader([]byte("body")))
			request.Header.Set("Content-Type", "application/json")
			captured, oversized, err := captureRequestBody(request, RequestBodyConfig{
				Enabled: true, MaximumBytes: 32, ContentTypes: []string{"application/json"},
				BypassPathPrefix: []string{"/uploads"},
			}, test.protocol)
			if err != nil {
				t.Fatal(err)
			}
			if captured != nil || oversized {
				t.Fatalf("body was captured for %s", test.name)
			}
		})
	}
}
