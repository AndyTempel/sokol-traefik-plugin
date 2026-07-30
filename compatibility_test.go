package sokol_traefik_plugin

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type compatibilityWriter struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	flushes int
}

func (w *compatibilityWriter) Header() http.Header {
	return w.header
}

func (w *compatibilityWriter) WriteHeader(status int) {
	w.status = status
}

func (w *compatibilityWriter) Write(value []byte) (int, error) {
	return w.body.Write(value)
}

func (w *compatibilityWriter) Flush() {
	w.flushes++
}

func (w *compatibilityWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	server, client := net.Pipe()
	_ = client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}

func TestTransportAndStreamingCompatibilityUsesOriginalWriter(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		headers    map[string]string
		proto      string
		protoMajor int
		transfer   []string
		expected   string
	}{
		{name: "HTTP 1.1", method: "GET", proto: "HTTP/1.1", protoMajor: 1, expected: "http"},
		{name: "HTTP 2", method: "GET", proto: "HTTP/2.0", protoMajor: 2, expected: "http"},
		{name: "HTTP 3", method: "GET", proto: "HTTP/3.0", protoMajor: 3, expected: "http"},
		{
			name: "WebSocket", method: "GET", proto: "HTTP/1.1", protoMajor: 1, expected: "websocket",
			headers: map[string]string{"Connection": "keep-alive, Upgrade", "Upgrade": "websocket"},
		},
		{
			name: "Home Assistant style WebSocket", method: "GET", proto: "HTTP/1.1", protoMajor: 1, expected: "websocket",
			headers: map[string]string{
				"Connection": "Upgrade", "Upgrade": "websocket",
				"Sec-WebSocket-Protocol": "auth",
			},
		},
		{
			name: "SSE", method: "GET", proto: "HTTP/1.1", protoMajor: 1, expected: "sse",
			headers: map[string]string{"Accept": "text/event-stream"},
		},
		{
			name: "gRPC", method: "POST", proto: "HTTP/2.0", protoMajor: 2, expected: "grpc",
			headers: map[string]string{"Content-Type": "application/grpc+proto"},
		},
		{name: "WebDAV", method: "PROPFIND", proto: "HTTP/1.1", protoMajor: 1, expected: "webdav"},
		{
			name: "chunked request", method: "POST", proto: "HTTP/1.1", protoMajor: 1,
			transfer: []string{"chunked"}, expected: "http",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentFixture(t)
			var originalWriter *compatibilityWriter
			var downstream atomic.Int64
			handler := newMiddleware(t, testConfig(t, fixture), http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if writer != originalWriter {
					t.Fatal("middleware replaced the downstream response writer")
				}
				downstream.Add(1)
				_, _ = writer.Write([]byte("first"))
				writer.(http.Flusher).Flush()
				_, _ = writer.Write([]byte("second"))
			}))
			request := httptest.NewRequest(test.method, "http://example.test/stream", nil)
			request.RemoteAddr = "198.51.100.2:1234"
			request.Proto = test.proto
			request.ProtoMajor = test.protoMajor
			request.ProtoMinor = 0
			request.TransferEncoding = test.transfer
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			originalWriter = &compatibilityWriter{header: make(http.Header)}
			handler.ServeHTTP(originalWriter, request)
			input := <-fixture.inputs
			if input.ProtocolType != test.expected {
				t.Fatalf("protocol type = %q", input.ProtocolType)
			}
			if input.HTTPVersion != test.proto {
				t.Fatalf("HTTP version = %q", input.HTTPVersion)
			}
			if len(test.transfer) > 0 && input.Headers["transfer-encoding"] != "chunked" {
				t.Fatalf("transfer encoding = %q", input.Headers["transfer-encoding"])
			}
			if downstream.Load() != 1 || originalWriter.body.String() != "firstsecond" || originalWriter.flushes != 1 {
				t.Fatalf("downstream=%d body=%q flushes=%d", downstream.Load(), originalWriter.body.String(), originalWriter.flushes)
			}
		})
	}
}

type observedBody struct {
	reads atomic.Int64
}

func (b *observedBody) Read(_ []byte) (int, error) {
	b.reads.Add(1)
	return 0, io.EOF
}

func (b *observedBody) Close() error {
	return nil
}

func TestWebSocketBodyIsNeverRead(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.RequestBody.Enabled = true
	body := &observedBody{}
	handler := newMiddleware(t, config, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	request := httptest.NewRequest("GET", "http://example.test/socket", nil)
	request.RemoteAddr = "198.51.100.2:1234"
	request.Body = body
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	input := <-fixture.inputs
	if body.reads.Load() != 0 || len(input.Body) != 0 {
		t.Fatalf("body reads=%d agent body=%q", body.reads.Load(), input.Body)
	}
}

func TestLargeUploadAndDownloadAreNotBufferedByMiddleware(t *testing.T) {
	fixture := newAgentFixture(t)
	config := testConfig(t, fixture)
	config.RequestBody.Enabled = true
	config.RequestBody.BypassPathPrefix = []string{"/uploads"}
	upload := bytes.Repeat([]byte("u"), 2<<20)
	var received int
	handler := newMiddleware(t, config, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		data, _ := io.ReadAll(request.Body)
		received = len(data)
		_, _ = writer.Write(bytes.Repeat([]byte("d"), 2<<20))
	}))
	request := httptest.NewRequest("POST", "http://example.test/uploads/archive", bytes.NewReader(upload))
	request.RemoteAddr = "198.51.100.2:1234"
	request.Header.Set("Content-Type", "multipart/form-data; boundary=example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	input := <-fixture.inputs
	if received != len(upload) || len(input.Body) != 0 || input.BodyTruncated || response.Body.Len() != 2<<20 {
		t.Fatalf("upload=%d agent body=%d truncated=%t download=%d", received, len(input.Body), input.BodyTruncated, response.Body.Len())
	}
}

func TestPageReloadUsesThrottledCache(t *testing.T) {
	root := t.TempDir()
	config := CreateConfig().Responses
	config.Root = root
	config.ReloadInterval = "1s"
	store := newPageStore(config, root, time.Second)
	path := filepath.Join(root, config.BlockFile)
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if got := string(store.page("block", start)); got != "first" {
		t.Fatalf("first page = %q", got)
	}
	if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := string(store.page("block", start.Add(500*time.Millisecond))); got != "first" {
		t.Fatalf("cache was not throttled: %q", got)
	}
	if got := string(store.page("block", start.Add(2*time.Second))); got != "second" {
		t.Fatalf("page did not reload: %q", got)
	}
}

func TestPageSymlinkPolicyAndRootContainment(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.html")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := CreateConfig().Responses
	config.Root = root
	config.BlockFile = "linked.html"
	if err := os.Symlink(outside, filepath.Join(root, config.BlockFile)); err != nil {
		t.Fatal(err)
	}
	store := newPageStore(config, root, time.Second)
	if got := string(store.page("block", time.Now())); got != fallbackPage {
		t.Fatalf("external symlink was loaded: %q", got)
	}
	pluginConfig := CreateConfig()
	pluginConfig.Responses.Root = root
	pluginConfig.Responses.BlockFile = "../outside.html"
	pluginConfig.Agent.TokenFile = filepath.Join(root, "missing-token")
	if _, err := validateConfig(pluginConfig); err == nil {
		t.Fatal("path traversal configuration was accepted")
	}
}

func TestDecisionCacheCardinalityIsBounded(t *testing.T) {
	cache := newDecisionCache(3, time.Second)
	now := time.Now()
	for index := 0; index < 100; index++ {
		request := evaluationRequest{
			ClientIP: "203.0.113.1", Method: "GET", Scheme: "https", Host: "example.test",
			Path: string(rune('a' + index)), ProtocolType: "http",
		}
		cache.put(request, evaluationResponse{
			Decision: "block", Status: 403, PublicReason: "request_blocked",
			CacheTTLMS: 1000, Cacheable: true, CacheKey: strings.Repeat("a", 64),
			CacheKeyScope: "request", DecisionScope: "resource:resource-1",
			PolicyRevision: 1, ResourceID: "resource-1",
		}, now.Add(time.Duration(index)*time.Microsecond))
	}
	cache.mu.Lock()
	length := len(cache.entries)
	cache.mu.Unlock()
	if length != 3 {
		t.Fatalf("cache entries = %d", length)
	}
}
