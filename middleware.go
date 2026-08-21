package sokol_traefik_plugin

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func (m *Middleware) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	requestID := normalizedRequestID(request.Header.Get("X-Request-ID"))
	protocol := protocolType(request)
	clientIP, clientIPSource, ipError := extractClientIPWithSource(
		request,
		m.config.ClientIP,
		m.runtime.trusted,
		m.providers,
	)
	if clientIP == nil {
		m.handleFailure(writer, request, requestID, agentUnavailable)
		return
	}
	if ipError != nil {
		log.Printf("sokol middleware %q: ignored malformed trusted client IP metadata", m.name)
	}
	if m.handleChallengeEndpoint(writer, request, requestID, clientIP) {
		return
	}
	if !validInboundMetadata(request) {
		m.pages.write(writer, request, evaluationResponse{
			Decision: "error", Status: http.StatusBadRequest, RequestID: requestID,
			PublicReason: "invalid_request",
		})
		return
	}
	body, oversized, err := captureRequestBody(request, m.config.RequestBody, protocol)
	if err != nil {
		m.handleFailure(writer, request, requestID, agentUnavailable)
		return
	}
	if oversized && m.config.RequestBody.OversizeAction == "reject" {
		m.pages.write(writer, request, evaluationResponse{
			Decision: "error", Status: http.StatusRequestEntityTooLarge, RequestID: requestID,
			PublicReason: "request_body_too_large",
		})
		return
	}
	if oversized {
		body = nil
	}
	input := evaluationRequest{
		RequestID:      requestID,
		ClientIP:       clientIP.String(),
		ClientIPSource: clientIPSource,
		Method:         strings.ToUpper(request.Method),
		Scheme:         requestScheme(request, m.runtime.trusted),
		Host:           request.Host,
		Path:           request.URL.Path,
		Query:          request.URL.RawQuery,
		Headers:        m.selectedHeaders(request),
		Cookies:        m.selectedRequestCookies(request),
		ProtocolType:   protocol,
		HTTPVersion:    request.Proto,
		Body:           body,
		BodyTruncated:  oversized,
		ResourceHint:   m.config.ResourceHint,
	}
	if input.Path == "" {
		input.Path = "/"
	}
	now := time.Now()
	if cached, ok := m.cache.get(input, requestID, now); ok {
		m.handleDecision(writer, request, cached)
		return
	}
	if !m.breaker.allow(now) {
		m.handleFailure(writer, request, requestID, agentUnavailable)
		return
	}
	response, err := m.agent.evaluate(request.Context(), input)
	if err != nil {
		kind := agentUnavailable
		if localError, ok := err.(*agentError); ok {
			kind = localError.kind
		}
		m.breaker.failure(now)
		m.handleFailure(writer, request, requestID, kind)
		return
	}
	m.breaker.success()
	if response.Decision == "error" {
		m.handleFailure(writer, request, requestID, agentUnavailable)
		return
	}
	m.cache.put(input, response, now)
	m.handleDecision(writer, request, response)
}

func (m *Middleware) handleDecision(writer http.ResponseWriter, request *http.Request, response evaluationResponse) {
	switch response.Decision {
	case "allow", "observe":
		m.next.ServeHTTP(writer, request)
	case "block", "challenge", "rate_limit":
		if m.config.FailureMode.ExplicitLocalDeny == "allow" {
			m.next.ServeHTTP(writer, request)
			return
		}
		if response.Decision == "challenge" {
			response.ChallengeURL = m.config.Challenge.PathPrefix + "/challenge"
		}
		m.pages.write(writer, request, response)
	default:
		m.handleFailure(writer, request, response.RequestID, agentMalformed)
	}
}

func (m *Middleware) handleFailure(writer http.ResponseWriter, request *http.Request, requestID string, kind agentErrorKind) {
	mode := m.config.FailureMode.AgentUnavailable
	reason := "edge_agent_unavailable"
	if kind == agentMalformed {
		mode = m.config.FailureMode.MalformedResponse
		reason = "edge_agent_invalid_response"
	}
	log.Printf("sokol middleware %q: %s", m.name, reason)
	if mode == "allow" {
		m.next.ServeHTTP(writer, request)
		return
	}
	m.pages.write(writer, request, evaluationResponse{
		Decision: "error", Status: http.StatusServiceUnavailable, RequestID: requestID,
		PublicReason: reason,
	})
}

func (m *Middleware) selectedHeaders(request *http.Request) map[string]string {
	result := make(map[string]string, len(m.selectedHeads)+2)
	for _, name := range m.selectedHeads {
		values := request.Header.Values(name)
		if len(values) == 0 {
			continue
		}
		value := strings.Join(values, ", ")
		if len(value) > 4096 {
			value = value[:4096]
		}
		result[strings.ToLower(name)] = value
	}
	if request.ContentLength >= 0 &&
		request.Method != http.MethodGet && request.Method != http.MethodHead {
		result["content-length"] = strconv.FormatInt(request.ContentLength, 10)
	}
	if len(request.TransferEncoding) > 0 {
		result["transfer-encoding"] = strings.Join(request.TransferEncoding, ", ")
	}
	return result
}

func (m *Middleware) selectedRequestCookies(request *http.Request) map[string]string {
	result := make(map[string]string, len(m.selectedCookies))
	for _, cookie := range request.Cookies() {
		if _, ok := m.selectedCookies[cookie.Name]; ok && len(cookie.Value) <= 4096 {
			result[cookie.Name] = cookie.Value
		}
	}
	return result
}

func normalizedRequestID(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 1 && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00") {
		return value
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err == nil {
		return hex.EncodeToString(random)
	}
	return hex.EncodeToString([]byte(time.Now().UTC().Format("20060102150405.000000000")))
}

func validInboundMetadata(request *http.Request) bool {
	if len(request.Method) < 1 || len(request.Method) > 32 ||
		len(request.Host) < 1 || len(request.Host) > 253 ||
		len(request.URL.Path) > 8192 || len(request.URL.RawQuery) > 8192 ||
		strings.ContainsAny(request.Host, "\r\n\x00") ||
		!utf8.ValidString(request.URL.Path) ||
		!strings.HasPrefix(request.URL.Path, "/") ||
		strings.ContainsAny(request.URL.Path, "\x00?#") {
		return false
	}
	for _, segment := range strings.Split(request.URL.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func requestScheme(request *http.Request, trusted []*net.IPNet) string {
	if request.TLS != nil {
		return "https"
	}
	direct, err := parseRemoteIP(request.RemoteAddr)
	if err == nil && ipIsTrusted(direct, trusted) {
		forwarded := strings.TrimSpace(strings.ToLower(request.Header.Get("X-Forwarded-Proto")))
		if forwarded == "https" || forwarded == "http" {
			return forwarded
		}
	}
	return "http"
}

func protocolType(request *http.Request) string {
	if headerHasToken(request.Header, "Connection", "upgrade") &&
		strings.EqualFold(strings.TrimSpace(request.Header.Get("Upgrade")), "websocket") {
		return "websocket"
	}
	contentType := strings.ToLower(request.Header.Get("Content-Type"))
	if strings.HasPrefix(contentType, "application/grpc") {
		return "grpc"
	}
	if headerHasToken(request.Header, "Accept", "text/event-stream") {
		return "sse"
	}
	switch strings.ToUpper(request.Method) {
	case "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT", "SEARCH":
		return "webdav"
	}
	return "http"
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, item := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(item), token) {
				return true
			}
		}
	}
	return false
}
