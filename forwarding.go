package sokol_traefik_plugin

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Forwarding modes for request headers and cookies. "all" forwards every
// value within the bounds below; "allowlist" forwards only configured names.
const (
	forwardAll       = "all"
	forwardAllowlist = "allowlist"
)

// Bounds applied before a request is described to the local Agent. They sit
// below the Agent's own limits so that an unusually large but legitimate
// browser request is truncated deterministically and flagged instead of being
// rejected as invalid.
const (
	maximumForwardedValueBytes  = 4096
	maximumForwardedNameBytes   = 128
	maximumForwardedHeaders     = 128
	maximumForwardedCookies     = 128
	maximumForwardedHeaderBytes = 64 << 10
	maximumForwardedCookieBytes = 64 << 10
	defaultTrustCookieName      = "__Host-sokol_trust"
	cookieHeaderKey             = "cookie"
)

// legacyDefaultHeaders is the allowlist used before every header was
// forwarded. In "all" mode it still names the headers whose WAF matches keep
// enforcing while newly visible headers follow the WAF policy's
// extended-data mode.
var legacyDefaultHeaders = []string{
	"Accept",
	"Content-Type",
	"User-Agent",
	"Origin",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Upgrade",
	"Connection",
	"Sec-WebSocket-Protocol",
	"Sec-WebSocket-Version",
}

type forwardingPolicy struct {
	allHeaders bool
	allCookies bool
	// headers and cookies hold the configured names in configuration order.
	headers []string
	cookies []string
	// headerSet and cookieSet index the configured names.
	headerSet map[string]struct{}
	cookieSet map[string]struct{}
	// allowlistedHeaders/Cookies are sent to the Agent in "all" mode so it can
	// tell previously visible data from newly visible data.
	allowlistedHeaders []string
	allowlistedCookies []string
}

func newForwardingPolicy(config RequestConfig) forwardingPolicy {
	policy := forwardingPolicy{
		allHeaders: config.HeaderMode == forwardAll,
		allCookies: config.CookieMode == forwardAll,
		headerSet:  make(map[string]struct{}, len(config.Headers)),
		cookieSet:  make(map[string]struct{}, len(config.Cookies)),
	}
	for _, header := range config.Headers {
		canonical := http.CanonicalHeaderKey(header)
		if _, exists := policy.headerSet[canonical]; exists {
			continue
		}
		policy.headerSet[canonical] = struct{}{}
		policy.headers = append(policy.headers, canonical)
		if policy.allHeaders {
			policy.allowlistedHeaders = append(policy.allowlistedHeaders, strings.ToLower(canonical))
		}
	}
	for _, cookie := range config.Cookies {
		if _, exists := policy.cookieSet[cookie]; exists {
			continue
		}
		policy.cookieSet[cookie] = struct{}{}
		policy.cookies = append(policy.cookies, cookie)
		if policy.allCookies {
			policy.allowlistedCookies = append(policy.allowlistedCookies, cookie)
		}
	}
	return policy
}

// forwardedHeaders returns the forwarded headers and whether anything was omitted or
// shortened. Configured names are taken first, then the remainder in sorted
// order, so truncation never depends on map iteration or arrival order.
func (p forwardingPolicy) forwardedHeaders(request *http.Request) (map[string]string, bool) {
	names := make([]string, 0, len(p.headers))
	names = append(names, p.headers...)
	if p.allHeaders {
		remaining := make([]string, 0, len(request.Header))
		for name := range request.Header {
			canonical := http.CanonicalHeaderKey(name)
			if _, configured := p.headerSet[canonical]; configured {
				continue
			}
			remaining = append(remaining, name)
		}
		sort.Slice(remaining, func(i, j int) bool {
			return strings.ToLower(remaining[i]) < strings.ToLower(remaining[j])
		})
		names = append(names, remaining...)
	}
	result := make(map[string]string, len(names)+2)
	truncated := false
	total := 0
	for _, name := range names {
		values := request.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		key := strings.ToLower(name)
		if key == cookieHeaderKey {
			// Cookies are forwarded separately and rebuilt by the Agent.
			continue
		}
		if _, duplicate := result[key]; duplicate {
			continue
		}
		if len(key) > maximumForwardedNameBytes || !validHeaderName(key) {
			truncated = true
			continue
		}
		value := strings.Join(values, ", ")
		if strings.ContainsAny(value, "\x00\r\n") {
			truncated = true
			continue
		}
		if len(value) > maximumForwardedValueBytes {
			value = value[:maximumForwardedValueBytes]
			truncated = true
		}
		if len(result) >= maximumForwardedHeaders ||
			total+len(key)+len(value) > maximumForwardedHeaderBytes {
			truncated = true
			continue
		}
		total += len(key) + len(value)
		result[key] = value
	}
	if request.ContentLength >= 0 &&
		request.Method != http.MethodGet && request.Method != http.MethodHead {
		result["content-length"] = strconv.FormatInt(request.ContentLength, 10)
	}
	if len(request.TransferEncoding) > 0 {
		result["transfer-encoding"] = strings.Join(request.TransferEncoding, ", ")
	}
	return result, truncated
}

// forwardedCookies applies the same deterministic ordering to cookies. When a
// name repeats, the first occurrence is kept and the request is flagged.
func (p forwardingPolicy) forwardedCookies(request *http.Request) (map[string]string, bool) {
	parsed := request.Cookies()
	first := make(map[string]string, len(parsed))
	order := make([]string, 0, len(parsed))
	truncated := false
	for _, cookie := range parsed {
		if _, exists := first[cookie.Name]; exists {
			truncated = true
			continue
		}
		first[cookie.Name] = cookie.Value
		order = append(order, cookie.Name)
	}
	names := make([]string, 0, len(order))
	for _, name := range p.cookies {
		if _, present := first[name]; present {
			names = append(names, name)
		}
	}
	if p.allCookies {
		remaining := make([]string, 0, len(order))
		for _, name := range order {
			if _, configured := p.cookieSet[name]; !configured {
				remaining = append(remaining, name)
			}
		}
		sort.Strings(remaining)
		names = append(names, remaining...)
	}
	result := make(map[string]string, len(names))
	total := 0
	for _, name := range names {
		value := first[name]
		if !validCookieName(name) || strings.ContainsAny(value, "\x00\r\n") {
			truncated = true
			continue
		}
		if len(value) > maximumForwardedValueBytes {
			value = value[:maximumForwardedValueBytes]
			truncated = true
		}
		if len(result) >= maximumForwardedCookies ||
			total+len(name)+len(value) > maximumForwardedCookieBytes {
			truncated = true
			continue
		}
		total += len(name) + len(value)
		result[name] = value
	}
	return result, truncated
}
