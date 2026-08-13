package sokol_traefik_plugin

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type browserVerifyRequest struct {
	ChallengeToken string          `json:"challenge_token"`
	ResourceID     string          `json:"resource_id"`
	SiteID         string          `json:"site_id"`
	Path           string          `json:"path"`
	Payload        json.RawMessage `json:"payload"`
}

func (m *Middleware) handleChallengeEndpoint(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	clientIP net.IP,
) bool {
	createPath := m.config.Challenge.PathPrefix + "/challenge"
	verifyPath := createPath + "/verify"
	switch {
	case request.URL.Path == createPath && request.Method == http.MethodGet:
		m.challengeCreate(writer, request, requestID, clientIP)
		return true
	case request.URL.Path == verifyPath && request.Method == http.MethodPost:
		m.challengeVerify(writer, request, requestID, clientIP)
		return true
	case strings.HasPrefix(request.URL.Path, m.config.Challenge.PathPrefix+"/"):
		setEnforcementHeaders(writer.Header())
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(writer).Encode(map[string]interface{}{
			"verified": false, "public_reason": "challenge_endpoint_not_found",
			"request_id": requestID,
		})
		return true
	default:
		return false
	}
}

func (m *Middleware) challengeCreate(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	clientIP net.IP,
) {
	query := request.URL.Query()
	token := query.Get("token")
	resourceID := query.Get("resource")
	siteID := query.Get("site")
	path := query.Get("path")
	if !validChallengeFields(token, resourceID, siteID, path) {
		writeChallengeError(writer, http.StatusBadRequest, requestID, "challenge_invalid")
		return
	}
	output, err := m.agent.challengeCreate(request.Context(), requestID, challengeCreateRequest{
		ChallengeToken: token,
		Context: challengeContext{
			ResourceID: resourceID, SiteID: siteID, ClientIP: clientIP.String(),
			UserAgent: boundedUserAgent(request), Path: path,
		},
	})
	if err != nil {
		log.Printf(
			"sokol middleware %q: challenge creation failed request_id=%s resource_id=%s site_id=%s error=%v",
			m.name, requestID, resourceID, siteID, err,
		)
		writeChallengeError(writer, http.StatusForbidden, requestID, "challenge_invalid")
		return
	}
	setEnforcementHeaders(writer.Header())
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(output)
}

func (m *Middleware) challengeVerify(
	writer http.ResponseWriter,
	request *http.Request,
	requestID string,
	clientIP net.IP,
) {
	if !sameOriginSubmission(request, m.runtime.trusted) {
		writeChallengeError(writer, http.StatusForbidden, requestID, "challenge_origin_rejected")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, m.config.Challenge.MaximumBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input browserVerifyRequest
	if err := decoder.Decode(&input); err != nil {
		var maximumError *http.MaxBytesError
		if errors.As(err, &maximumError) {
			writeChallengeError(writer, http.StatusRequestEntityTooLarge, requestID, "request_too_large")
			return
		}
		writeChallengeError(writer, http.StatusBadRequest, requestID, "challenge_invalid")
		return
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) ||
		!validChallengeFields(input.ChallengeToken, input.ResourceID, input.SiteID, input.Path) ||
		len(input.Payload) < 2 || len(input.Payload) > int(m.config.Challenge.MaximumBodyBytes) {
		writeChallengeError(writer, http.StatusBadRequest, requestID, "challenge_invalid")
		return
	}
	output, err := m.agent.challengeVerify(request.Context(), requestID, challengeVerifyRequest{
		Token:   input.ChallengeToken,
		Payload: input.Payload,
		Context: challengeContext{
			ResourceID: input.ResourceID, SiteID: input.SiteID, ClientIP: clientIP.String(),
			UserAgent: boundedUserAgent(request), Path: input.Path,
		},
	})
	if err != nil {
		log.Printf(
			"sokol middleware %q: challenge verification failed request_id=%s resource_id=%s site_id=%s error=%v",
			m.name, requestID, input.ResourceID, input.SiteID, err,
		)
		writeChallengeError(writer, http.StatusServiceUnavailable, requestID, "challenge_verification_error")
		return
	}
	if output.Verified {
		http.SetCookie(writer, &http.Cookie{
			Name: output.CookieName, Value: output.CookieValue,
			Path: "/", MaxAge: output.CookieMaxAge,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	setEnforcementHeaders(writer.Header())
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(writer).Encode(map[string]interface{}{
		"verified": output.Verified, "public_reason": output.PublicReason,
		"request_id": requestID,
	})
}

func validChallengeFields(token, resourceID, siteID, path string) bool {
	return len(token) >= 32 && len(token) <= 4096 &&
		len(resourceID) >= 1 && len(resourceID) <= 128 &&
		len(siteID) >= 1 && len(siteID) <= 128 &&
		len(path) >= 1 && len(path) <= 8192 && strings.HasPrefix(path, "/") &&
		!strings.HasPrefix(path, "//") && !strings.Contains(path, "\\") &&
		!strings.ContainsAny(token+resourceID+siteID+path, "\x00\r\n")
}

func boundedUserAgent(request *http.Request) string {
	value := request.UserAgent()
	if len(value) > 4096 {
		value = value[:4096]
	}
	return value
}

func sameOriginSubmission(request *http.Request, trusted []*net.IPNet) bool {
	origin := strings.TrimSpace(request.Header.Get("Origin"))
	if origin == "" {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" {
		return false
	}
	expectedScheme := requestScheme(request, trusted)
	return strings.EqualFold(parsed.Scheme, expectedScheme) &&
		strings.EqualFold(parsed.Host, request.Host)
}

func writeChallengeError(
	writer http.ResponseWriter,
	status int,
	requestID, reason string,
) {
	setEnforcementHeaders(writer.Header())
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]interface{}{
		"verified": false, "public_reason": reason, "request_id": requestID,
	})
}
