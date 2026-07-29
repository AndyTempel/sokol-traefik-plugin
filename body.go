package sokol_traefik_plugin

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strings"
)

type replayReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r *replayReadCloser) Close() error {
	return r.closer.Close()
}

func captureRequestBody(request *http.Request, config RequestBodyConfig, protocol string) ([]byte, bool, error) {
	if !config.Enabled || request.Body == nil || request.Body == http.NoBody ||
		protocol != "http" || bypassBodyPath(request.URL.Path, config.BypassPathPrefix) ||
		!bodyContentTypeAllowed(request.Header.Get("Content-Type"), config.ContentTypes) {
		return nil, false, nil
	}
	limit := config.MaximumBytes
	prefix, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	request.Body = &replayReadCloser{
		Reader: io.MultiReader(bytes.NewReader(prefix), request.Body),
		closer: request.Body,
	}
	if err != nil {
		return nil, false, err
	}
	if int64(len(prefix)) > limit {
		return nil, true, nil
	}
	return prefix, false, nil
}

func bodyContentTypeAllowed(value string, allowed []string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	mediaType = strings.ToLower(mediaType)
	for _, pattern := range allowed {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == mediaType {
			return true
		}
		if strings.HasSuffix(pattern, "/*") && strings.HasPrefix(mediaType, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	return false
}

func bypassBodyPath(path string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if prefix == "/" || path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}
