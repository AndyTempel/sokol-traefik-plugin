package sokol_traefik_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const maximumAgentResponseBytes = 32 << 10

type evaluationRequest struct {
	RequestID     string            `json:"request_id"`
	ClientIP      string            `json:"client_ip"`
	Method        string            `json:"method"`
	Scheme        string            `json:"scheme"`
	Host          string            `json:"host"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Headers       map[string]string `json:"headers"`
	Cookies       map[string]string `json:"cookies"`
	ProtocolType  string            `json:"protocol_type"`
	HTTPVersion   string            `json:"http_version,omitempty"`
	Body          []byte            `json:"body,omitempty"`
	BodyTruncated bool              `json:"body_truncated,omitempty"`
	ResourceHint  string            `json:"resource_hint,omitempty"`
}

type evaluationResponse struct {
	Decision           string `json:"decision"`
	Status             int    `json:"status"`
	RequestID          string `json:"request_id"`
	PublicReason       string `json:"public_reason"`
	CacheTTLMS         int    `json:"cache_ttl_ms"`
	ResourceID         string `json:"resource_id,omitempty"`
	SiteID             string `json:"site_id,omitempty"`
	ChallengeURL       string `json:"challenge_url,omitempty"`
	ChallengeToken     string `json:"challenge_token,omitempty"`
	ChallengeAutoStart bool   `json:"challenge_auto_start,omitempty"`
	Cacheable          bool   `json:"cacheable,omitempty"`
	CacheKey           string `json:"cache_key,omitempty"`
	CacheKeyScope      string `json:"cache_key_scope,omitempty"`
	DecisionScope      string `json:"decision_scope,omitempty"`
	PolicyRevision     uint64 `json:"policy_revision,omitempty"`
}

type agentErrorKind int

const (
	agentUnavailable agentErrorKind = iota
	agentMalformed
)

type agentError struct {
	kind agentErrorKind
	err  error
}

func (e *agentError) Error() string {
	return e.err.Error()
}

type agentClient struct {
	client             *http.Client
	evaluateURL        string
	challengeCreateURL string
	challengeVerifyURL string
	token              string
	timeout            time.Duration
}

func newAgentClient(endpoint, token string, connectTimeout, requestTimeout time.Duration) (*agentClient, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: connectTimeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialLocalAgent(ctx, dialer, network, address)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   connectTimeout,
		ResponseHeaderTimeout: requestTimeout,
		ExpectContinueTimeout: 100 * time.Millisecond,
	}
	evaluateURL := strings.TrimSuffix(endpoint, "/") + "/v1/evaluate"
	challengeCreateURL := strings.TrimSuffix(endpoint, "/") + "/v1/challenge/create"
	challengeVerifyURL := strings.TrimSuffix(endpoint, "/") + "/v1/challenge/verify"
	if parsed.Scheme == "unix" {
		socketPath := filepath.Clean(parsed.Path)
		transport.ForceAttemptHTTP2 = false
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socketPath)
		}
		evaluateURL = "http://sokol-edge-agent/v1/evaluate"
		challengeCreateURL = "http://sokol-edge-agent/v1/challenge/create"
		challengeVerifyURL = "http://sokol-edge-agent/v1/challenge/verify"
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("agent redirects are forbidden")
		},
	}
	return &agentClient{
		client: client, evaluateURL: evaluateURL,
		challengeCreateURL: challengeCreateURL, challengeVerifyURL: challengeVerifyURL,
		token: token, timeout: requestTimeout,
	}, nil
}

func dialLocalAgent(ctx context.Context, dialer *net.Dialer, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("local agent dial address is invalid")
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if !localAgentIP(ip) {
			return nil, errors.New("local agent resolved to a public address")
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve local agent: %w", err)
	}
	if len(addresses) > 16 {
		addresses = addresses[:16]
	}
	var lastError error
	for _, candidate := range addresses {
		if !localAgentIP(candidate.IP) {
			continue
		}
		connection, err := dialer.DialContext(
			ctx, network, net.JoinHostPort(candidate.IP.String(), port),
		)
		if err == nil {
			return connection, nil
		}
		lastError = err
	}
	if lastError != nil {
		return nil, fmt.Errorf("connect to local agent: %w", lastError)
	}
	return nil, errors.New("local agent DNS name did not resolve to a local address")
}

func (c *agentClient) evaluate(parent context.Context, input evaluationRequest) (evaluationResponse, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("encode local evaluation")}
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.evaluateURL, bytes.NewReader(encoded))
	if err != nil {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("construct local evaluation")}
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		return evaluationResponse{}, &agentError{kind: agentUnavailable, err: fmt.Errorf("local agent request: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return evaluationResponse{}, &agentError{kind: agentUnavailable, err: fmt.Errorf("local agent status %d", response.StatusCode)}
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/json") {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("local agent returned a non-JSON response")}
	}
	limited := &io.LimitedReader{R: response.Body, N: maximumAgentResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var output evaluationResponse
	if err := decoder.Decode(&output); err != nil {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("decode local agent response")}
	}
	if limited.N <= 0 {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("local agent response exceeds limit")}
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: errors.New("local agent response has trailing data")}
	}
	if err := validateEvaluationResponse(input.RequestID, output); err != nil {
		return evaluationResponse{}, &agentError{kind: agentMalformed, err: err}
	}
	return output, nil
}

func validateEvaluationResponse(requestID string, response evaluationResponse) error {
	if response.RequestID != requestID {
		return errors.New("local agent response request ID mismatch")
	}
	expectedStatus := 0
	switch response.Decision {
	case "allow", "observe":
		expectedStatus = http.StatusOK
	case "block", "challenge":
		expectedStatus = http.StatusForbidden
	case "rate_limit":
		expectedStatus = http.StatusTooManyRequests
	case "error":
		if response.Status < 400 || response.Status > 599 {
			return errors.New("local agent error status is invalid")
		}
	default:
		return errors.New("local agent decision is invalid")
	}
	if expectedStatus != 0 && response.Status != expectedStatus {
		return errors.New("local agent status does not match decision")
	}
	if !validPublicReason(response.PublicReason) || len(response.ResourceID) > 128 ||
		len(response.SiteID) > 128 {
		return errors.New("local agent public fields are invalid")
	}
	if response.CacheTTLMS < 0 || response.CacheTTLMS > int(maximumCacheTTL/time.Millisecond) {
		return errors.New("local agent cache TTL is invalid")
	}
	if response.ChallengeURL != "" &&
		(!strings.HasPrefix(response.ChallengeURL, "/") || strings.HasPrefix(response.ChallengeURL, "//") ||
			len(response.ChallengeURL) > 2048 || strings.ContainsAny(response.ChallengeURL, "\r\n")) {
		return errors.New("local agent challenge URL is invalid")
	}
	if len(response.ChallengeToken) > 4096 || strings.ContainsAny(response.ChallengeToken, "\r\n") {
		return errors.New("local agent challenge token is invalid")
	}
	if response.Decision == "challenge" &&
		(response.ChallengeURL == "" || response.ChallengeToken == "" ||
			response.ResourceID == "" || response.SiteID == "") {
		return errors.New("local agent challenge response is incomplete")
	}
	if response.Cacheable {
		if response.Decision != "block" && response.Decision != "rate_limit" {
			return errors.New("only local deny decisions may be cached")
		}
		if response.CacheTTLMS <= 0 || len(response.CacheKey) != 64 ||
			response.CacheKeyScope != "request" ||
			len(response.DecisionScope) < 1 || len(response.DecisionScope) > 256 ||
			response.PolicyRevision == 0 ||
			!lowerHex(response.CacheKey) ||
			strings.ContainsAny(response.DecisionScope, "\r\n\x00") {
			return errors.New("local agent cache authorization is invalid")
		}
	} else if response.CacheKey != "" || response.CacheKeyScope != "" ||
		response.DecisionScope != "" || response.PolicyRevision != 0 {
		return errors.New("non-cacheable local response contains cache metadata")
	}
	return nil
}

type challengeContext struct {
	ResourceID string `json:"resource_id"`
	SiteID     string `json:"site_id"`
	ClientIP   string `json:"client_ip"`
	UserAgent  string `json:"user_agent"`
	Path       string `json:"path"`
}

type challengeCreateRequest struct {
	ChallengeToken string           `json:"challenge_token"`
	Context        challengeContext `json:"context"`
}

type challengeVerifyRequest struct {
	Token   string           `json:"challenge_token"`
	Payload json.RawMessage  `json:"payload"`
	Context challengeContext `json:"context"`
}

type challengeVerifyResponse struct {
	Verified     bool   `json:"verified"`
	PublicReason string `json:"public_reason"`
	CookieName   string `json:"cookie_name,omitempty"`
	CookieValue  string `json:"cookie_value,omitempty"`
	CookieMaxAge int    `json:"cookie_max_age,omitempty"`
}

func (c *agentClient) challengeCreate(
	parent context.Context,
	input challengeCreateRequest,
) (json.RawMessage, error) {
	var output json.RawMessage
	if err := c.challengeRequest(parent, c.challengeCreateURL, input, &output); err != nil {
		return nil, err
	}
	if len(output) == 0 {
		return nil, &agentError{kind: agentMalformed, err: errors.New("local challenge response is empty")}
	}
	return output, nil
}

func (c *agentClient) challengeVerify(
	parent context.Context,
	input challengeVerifyRequest,
) (challengeVerifyResponse, error) {
	var output challengeVerifyResponse
	if err := c.challengeRequest(parent, c.challengeVerifyURL, input, &output); err != nil {
		return challengeVerifyResponse{}, err
	}
	if !validPublicReason(output.PublicReason) || output.CookieMaxAge < 0 ||
		output.CookieMaxAge > 604800 || len(output.CookieValue) > 4096 {
		return challengeVerifyResponse{}, &agentError{
			kind: agentMalformed, err: errors.New("local challenge verification response is invalid"),
		}
	}
	if output.Verified && (output.CookieName != "__Host-sokol_trust" ||
		output.CookieValue == "" || output.CookieMaxAge == 0) {
		return challengeVerifyResponse{}, &agentError{
			kind: agentMalformed, err: errors.New("local challenge cookie response is invalid"),
		}
	}
	return output, nil
}

func (c *agentClient) challengeRequest(
	parent context.Context,
	endpoint string,
	input interface{},
	output interface{},
) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return &agentError{kind: agentMalformed, err: errors.New("encode local challenge request")}
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return &agentError{kind: agentMalformed, err: errors.New("construct local challenge request")}
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return &agentError{kind: agentUnavailable, err: fmt.Errorf("local challenge request: %w", err)}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return &agentError{kind: agentUnavailable, err: fmt.Errorf("local challenge status %d", response.StatusCode)}
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/json") {
		return &agentError{kind: agentMalformed, err: errors.New("local challenge returned non-JSON")}
	}
	limited := &io.LimitedReader{R: response.Body, N: maximumAgentResponseBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil || limited.N <= 0 {
		return &agentError{kind: agentMalformed, err: errors.New("decode local challenge response")}
	}
	var extra interface{}
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return &agentError{kind: agentMalformed, err: errors.New("local challenge response has trailing data")}
	}
	return nil
}

func lowerHex(value string) bool {
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validPublicReason(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
