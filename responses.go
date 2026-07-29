package sokol_traefik_plugin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const fallbackPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Request unavailable</title></head><body><main><h1>Request unavailable</h1>
<p>The request could not be completed.</p><p>Request ID: {{SOKOL_REQUEST_ID}}</p></main></body></html>`

type pageEntry struct {
	content   []byte
	nextCheck time.Time
}

type pageStore struct {
	mu             sync.Mutex
	config         ResponsesConfig
	root           string
	reloadInterval time.Duration
	cache          map[string]pageEntry
}

func newPageStore(config ResponsesConfig, root string, reloadInterval time.Duration) *pageStore {
	return &pageStore{
		config: config, root: root, reloadInterval: reloadInterval,
		cache: make(map[string]pageEntry),
	}
}

func (p *pageStore) write(writer http.ResponseWriter, request *http.Request, response evaluationResponse) {
	setEnforcementHeaders(writer.Header())
	status := enforcementStatus(response)
	if prefersJSON(request.Header.Get("Accept"), p.config.DefaultFormat) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(status)
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"decision":      response.Decision,
			"status":        status,
			"request_id":    response.RequestID,
			"public_reason": response.PublicReason,
		})
		return
	}
	nonce := randomNonce()
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Security-Policy",
		"default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; "+
			"img-src 'self' data:; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+"'")
	template := string(p.page(response.Decision, time.Now()))
	replacements := map[string]string{
		"{{SOKOL_REQUEST_ID}}":      html.EscapeString(response.RequestID),
		"{{SOKOL_HOST}}":            html.EscapeString(request.Host),
		"{{SOKOL_PATH}}":            html.EscapeString(request.URL.EscapedPath()),
		"{{SOKOL_TIMESTAMP}}":       html.EscapeString(time.Now().UTC().Format(time.RFC3339)),
		"{{SOKOL_CHALLENGE_URL}}":   html.EscapeString(response.ChallengeURL),
		"{{SOKOL_CHALLENGE_TOKEN}}": html.EscapeString(response.ChallengeToken),
		"{{SOKOL_CSP_NONCE}}":       html.EscapeString(nonce),
	}
	for placeholder, value := range replacements {
		template = strings.ReplaceAll(template, placeholder, value)
	}
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, template)
}

func (p *pageStore) page(decision string, now time.Time) []byte {
	name := p.config.UnavailableFile
	switch decision {
	case "block":
		name = p.config.BlockFile
	case "challenge":
		name = p.config.ChallengeFile
	case "rate_limit":
		name = p.config.RateLimitFile
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.cache[name]; ok && now.Before(entry.nextCheck) {
		return append([]byte(nil), entry.content...)
	}
	content, err := p.load(name)
	if err != nil {
		content = []byte(fallbackPage)
	}
	p.cache[name] = pageEntry{content: content, nextCheck: now.Add(p.reloadInterval)}
	return append([]byte(nil), content...)
}

func (p *pageStore) load(name string) ([]byte, error) {
	if err := validateRelativePagePath(p.root, name); err != nil {
		return nil, err
	}
	candidate := filepath.Clean(filepath.Join(p.root, name))
	resolvedRoot, err := filepath.EvalSymlinks(p.root)
	if err != nil {
		return nil, err
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, err
	}
	resolvedRoot = filepath.Clean(resolvedRoot)
	resolvedCandidate = filepath.Clean(resolvedCandidate)
	if !pathWithin(resolvedRoot, resolvedCandidate) {
		return nil, errors.New("page resolves outside root")
	}
	if !p.config.AllowSymlinks && (resolvedRoot != filepath.Clean(p.root) || resolvedCandidate != candidate) {
		return nil, errors.New("page symlinks are disabled")
	}
	file, err := os.Open(resolvedCandidate)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > p.config.MaximumFileBytes {
		return nil, errors.New("page must be a bounded regular file")
	}
	limited := &io.LimitedReader{R: file, N: p.config.MaximumFileBytes + 1}
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if limited.N <= 0 {
		return nil, errors.New("page exceeds maximum size")
	}
	if !utf8.Valid(content) {
		return nil, errors.New("page must use valid UTF-8")
	}
	return content, nil
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func setEnforcementHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store, private")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
}

func enforcementStatus(response evaluationResponse) int {
	switch response.Decision {
	case "block", "challenge":
		return http.StatusForbidden
	case "rate_limit":
		return http.StatusTooManyRequests
	case "error":
		if response.Status >= 400 && response.Status <= 599 {
			return response.Status
		}
		return http.StatusServiceUnavailable
	default:
		return http.StatusForbidden
	}
}

func prefersJSON(accept, defaultFormat string) bool {
	accept = strings.TrimSpace(strings.ToLower(accept))
	if accept == "" {
		return defaultFormat == "json"
	}
	jsonQuality, jsonOrder := mediaQuality(accept, "application/json")
	htmlQuality, htmlOrder := mediaQuality(accept, "text/html")
	if jsonQuality > htmlQuality {
		return true
	}
	if htmlQuality > jsonQuality {
		return false
	}
	if jsonQuality > 0 && htmlQuality > 0 && jsonOrder != htmlOrder {
		return jsonOrder < htmlOrder
	}
	return defaultFormat == "json"
}

func mediaQuality(accept, target string) (float64, int) {
	bestQuality := float64(-1)
	bestOrder := int(^uint(0) >> 1)
	targetParts := strings.Split(target, "/")
	for order, item := range strings.Split(accept, ",") {
		parts := strings.Split(item, ";")
		mediaType := strings.TrimSpace(parts[0])
		mediaParts := strings.Split(mediaType, "/")
		if len(mediaParts) != 2 ||
			mediaType != "*/*" &&
				mediaType != target &&
				!(mediaParts[0] == targetParts[0] && mediaParts[1] == "*") {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			name, value, ok := strings.Cut(strings.TrimSpace(parameter), "=")
			if ok && strings.TrimSpace(name) == "q" {
				parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
				if err != nil || parsed < 0 || parsed > 1 {
					quality = 0
				} else {
					quality = parsed
				}
			}
		}
		if quality > bestQuality {
			bestQuality = quality
			bestOrder = order
		}
	}
	if bestQuality < 0 {
		return 0, bestOrder
	}
	return bestQuality, bestOrder
}

func randomNonce() string {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
