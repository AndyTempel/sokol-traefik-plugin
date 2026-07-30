package sokol_traefik_plugin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
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

const fallbackChallengePage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta name="robots" content="noindex,nofollow"><title>Sokol verification</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b1220;color:#eef6f7;font-family:system-ui,sans-serif}main{width:min(36rem,calc(100% - 2rem));padding:2rem}button{padding:.7rem 1rem}#warning{color:#fde68a}</style></head>
<body><main id="challenge" data-url="{{SOKOL_CHALLENGE_URL}}" data-token="{{SOKOL_CHALLENGE_TOKEN}}" data-resource="{{SOKOL_CHALLENGE_RESOURCE_ID}}" data-site="{{SOKOL_CHALLENGE_SITE_ID}}" data-path="{{SOKOL_PATH}}" data-auto="{{SOKOL_CHALLENGE_AUTO_START}}">
<h1>Verification required</h1><p>Sokol needs a brief proof-of-work check.</p>
<sokol-captcha id="widget" name="sokol" challenge-url="{{SOKOL_CHALLENGE_URL}}" gate-submit="false" auto="off"></sokol-captcha>
<button id="start" type="button">Start verification</button><p id="status" role="status"></p>
<p id="warning" hidden>If verification assets are blocked, allow sokol-static.my-k.cloud and sokol.my-k.cloud, or disable the blocker for this site.</p>
<p>Request ID: {{SOKOL_REQUEST_ID}}</p></main>
<script nonce="{{SOKOL_CSP_NONCE}}" data-sokol-site="{{SOKOL_CHALLENGE_SITE_ID}}" src="https://sokol-static.my-k.cloud/v1/sokol.iife.js" defer></script>
<script nonce="{{SOKOL_CSP_NONCE}}">(()=>{const r=document.getElementById('challenge'),w=document.getElementById('widget'),b=document.getElementById('start'),s=document.getElementById('status'),n=document.getElementById('warning');let q=false;const blocked=()=>{n.hidden=false};const fail=()=>{blocked();s.textContent='Verification did not complete.';b.disabled=false;q=false};const run=async()=>{if(q)return;q=true;b.disabled=true;s.textContent='Verifying…';try{const x=await w.verify({timeout:180000}),i=r.querySelector('input[name="sokol"]'),p=x&&x.payload||i&&i.value;if(!p)throw Error('payload');const u=new URL(r.dataset.url,location.href),z=await fetch(u.pathname+'/verify',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({challenge_token:r.dataset.token,resource_id:r.dataset.resource,site_id:r.dataset.site,path:r.dataset.path,payload:p})}),j=await z.json();if(!z.ok||!j.verified)throw Error('rejected');const d=new URL(location.href);d.pathname=r.dataset.path;d.search='';d.hash='';location.assign(d.href)}catch(e){fail()}};b.addEventListener('click',run);const t=setTimeout(fail,8000);customElements.whenDefined('sokol-captcha').then(()=>{clearTimeout(t);if(r.dataset.auto==='true'){b.hidden=true;run()}}).catch(fail);fetch('https://sokol.my-k.cloud/api/tools/whoami',{mode:'cors',cache:'no-store',credentials:'include'}).catch(blocked)})()</script>
</body></html>`

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
			"img-src 'self' data: https://sokol-static.my-k.cloud; "+
			"style-src 'unsafe-inline' https://fonts.bunny.net https://sokol-static.my-k.cloud; "+
			"font-src https://fonts.bunny.net; "+
			"script-src 'nonce-"+nonce+"' https://sokol-static.my-k.cloud; "+
			"worker-src blob:; connect-src 'self' https://sokol-static.my-k.cloud https://sokol.my-k.cloud")
	challengeCreateURL := response.ChallengeURL + "?token=" +
		url.QueryEscape(response.ChallengeToken) + "&resource=" +
		url.QueryEscape(response.ResourceID) + "&site=" +
		url.QueryEscape(response.SiteID) + "&path=" +
		url.QueryEscape(request.URL.Path)
	template := string(p.page(response.Decision, time.Now()))
	replacements := map[string]string{
		"{{SOKOL_REQUEST_ID}}":            html.EscapeString(response.RequestID),
		"{{SOKOL_HOST}}":                  html.EscapeString(request.Host),
		"{{SOKOL_PATH}}":                  html.EscapeString(request.URL.EscapedPath()),
		"{{SOKOL_TIMESTAMP}}":             html.EscapeString(time.Now().UTC().Format(time.RFC3339)),
		"{{SOKOL_CHALLENGE_URL}}":         html.EscapeString(challengeCreateURL),
		"{{SOKOL_CHALLENGE_TOKEN}}":       html.EscapeString(response.ChallengeToken),
		"{{SOKOL_CHALLENGE_RESOURCE_ID}}": html.EscapeString(response.ResourceID),
		"{{SOKOL_CHALLENGE_SITE_ID}}":     html.EscapeString(response.SiteID),
		"{{SOKOL_CHALLENGE_AUTO_START}}":  strconv.FormatBool(response.ChallengeAutoStart),
		"{{SOKOL_CSP_NONCE}}":             html.EscapeString(nonce),
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
		if decision == "challenge" {
			content = []byte(fallbackChallengePage)
		}
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
