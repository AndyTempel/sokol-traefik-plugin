package sokol_traefik_plugin

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
)

type chunkedReadCloser struct {
	chunks [][]byte
	index  int
	offset int
	reads  int
}

func (r *chunkedReadCloser) Read(destination []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	r.reads++
	chunk := r.chunks[r.index]
	written := copy(destination, chunk[r.offset:])
	r.offset += written
	if r.offset == len(chunk) {
		r.index++
		r.offset = 0
	}
	return written, nil
}

func (r *chunkedReadCloser) Close() error { return nil }

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

func TestOrdinaryChunkedJSONIsCapturedAcrossChunkBoundaries(t *testing.T) {
	chunks := [][]byte{
		[]byte(`{"query":"1 UNI`),
		[]byte(`ON SELECT pass`),
		[]byte(`word FROM users"}`),
	}
	original := bytes.Join(chunks, nil)
	request := httptest.NewRequest("POST", "http://example.test/api", nil)
	request.Body = &chunkedReadCloser{chunks: chunks}
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Type", "application/json")
	if protocol := protocolType(request); protocol != "http" {
		t.Fatalf("ordinary chunked request classified as %q", protocol)
	}
	captured, oversized, err := captureRequestBody(request, RequestBodyConfig{
		Enabled: true, MaximumBytes: 1024, ContentTypes: []string{"application/json"},
	}, protocolType(request))
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
		t.Fatalf("downstream body changed: %q", restored)
	}
}

func TestOversizedChunkedBodyRestoresCapturedPrefixAndUnreadRemainder(t *testing.T) {
	chunks := [][]byte{
		bytes.Repeat([]byte("a"), 16),
		bytes.Repeat([]byte("b"), 16),
		bytes.Repeat([]byte("c"), 16),
		bytes.Repeat([]byte("d"), 16),
	}
	original := bytes.Join(chunks, nil)
	request := httptest.NewRequest("POST", "http://example.test/api", nil)
	request.Body = &chunkedReadCloser{chunks: chunks}
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Type", "application/json")
	captured, oversized, err := captureRequestBody(request, RequestBodyConfig{
		Enabled: true, MaximumBytes: 31, ContentTypes: []string{"application/json"},
	}, protocolType(request))
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
		t.Fatalf("restored %d bytes, want %d", len(restored), len(original))
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
			reader := &chunkedReadCloser{chunks: [][]byte{[]byte("body")}}
			request := httptest.NewRequest("POST", "http://example.test"+test.path, nil)
			request.Body = reader
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
			if reader.reads != 0 {
				t.Fatalf("body was read for %s", test.name)
			}
			downstream, err := io.ReadAll(request.Body)
			if err != nil || !bytes.Equal(downstream, []byte("body")) {
				t.Fatalf("downstream body for %s = %q, %v", test.name, downstream, err)
			}
		})
	}
}
