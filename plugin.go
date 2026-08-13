// Package sokol implements the thin Sokol Edge Traefik middleware.
//
// The middleware talks only to a local Sokol Edge Agent. It has no central
// backend client, persistent intelligence store, WAF engine, response-body
// wrapper, or route-management capability.
package sokol_traefik_plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maximumAgentTimeout     = 2 * time.Second
	maximumChallengeTimeout = 5 * time.Second
	maximumBodyBytes        = 1 << 20
	maximumCacheTTL         = 5 * time.Second
)

// Config is the Traefik dynamic middleware configuration.
type Config struct {
	Agent          AgentConfig          `json:"agent,omitempty" yaml:"agent,omitempty"`
	FailureMode    FailureModeConfig    `json:"failureMode,omitempty" yaml:"failureMode,omitempty"`
	ClientIP       ClientIPConfig       `json:"clientIP,omitempty" yaml:"clientIP,omitempty"`
	TrustedProxies []string             `json:"trustedProxies,omitempty" yaml:"trustedProxies,omitempty"`
	RequestBody    RequestBodyConfig    `json:"requestBody,omitempty" yaml:"requestBody,omitempty"`
	Request        RequestConfig        `json:"request,omitempty" yaml:"request,omitempty"`
	Responses      ResponsesConfig      `json:"responses,omitempty" yaml:"responses,omitempty"`
	Cache          CacheConfig          `json:"cache,omitempty" yaml:"cache,omitempty"`
	CircuitBreaker CircuitBreakerConfig `json:"circuitBreaker,omitempty" yaml:"circuitBreaker,omitempty"`
	Challenge      ChallengeConfig      `json:"challenge,omitempty" yaml:"challenge,omitempty"`
	ResourceHint   string               `json:"resourceHint,omitempty" yaml:"resourceHint,omitempty"`
}

type AgentConfig struct {
	Endpoint       string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	TokenFile      string `json:"tokenFile,omitempty" yaml:"tokenFile,omitempty"`
	ConnectTimeout string `json:"connectTimeout,omitempty" yaml:"connectTimeout,omitempty"`
	RequestTimeout string `json:"requestTimeout,omitempty" yaml:"requestTimeout,omitempty"`
}

type FailureModeConfig struct {
	AgentUnavailable  string `json:"agentUnavailable,omitempty" yaml:"agentUnavailable,omitempty"`
	MalformedResponse string `json:"malformedResponse,omitempty" yaml:"malformedResponse,omitempty"`
	ExplicitLocalDeny string `json:"explicitLocalDeny,omitempty" yaml:"explicitLocalDeny,omitempty"`
}

type ClientIPConfig struct {
	Strategy         string `json:"strategy,omitempty" yaml:"strategy,omitempty"`
	CloudflareHeader string `json:"cloudflareHeader,omitempty" yaml:"cloudflareHeader,omitempty"`
	// Deprecated: Cloudflare ranges are obtained from Cloudflare automatically.
	CloudflareCIDRs []string `json:"cloudflareCIDRs,omitempty" yaml:"cloudflareCIDRs,omitempty"`
	BunnyHeader     string   `json:"bunnyHeader,omitempty" yaml:"bunnyHeader,omitempty"`
	// Deprecated: Bunny ranges are obtained from Bunny automatically.
	BunnyCIDRs []string `json:"bunnyCIDRs,omitempty" yaml:"bunnyCIDRs,omitempty"`
}

type RequestBodyConfig struct {
	Enabled          bool     `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	MaximumBytes     int64    `json:"maximumBytes,omitempty" yaml:"maximumBytes,omitempty"`
	OversizeAction   string   `json:"oversizeAction,omitempty" yaml:"oversizeAction,omitempty"`
	ContentTypes     []string `json:"contentTypes,omitempty" yaml:"contentTypes,omitempty"`
	BypassPathPrefix []string `json:"bypassPathPrefixes,omitempty" yaml:"bypassPathPrefixes,omitempty"`
}

type RequestConfig struct {
	Headers []string `json:"headers,omitempty" yaml:"headers,omitempty"`
	Cookies []string `json:"cookies,omitempty" yaml:"cookies,omitempty"`
}

type ResponsesConfig struct {
	Root             string `json:"root,omitempty" yaml:"root,omitempty"`
	BlockFile        string `json:"blockFile,omitempty" yaml:"blockFile,omitempty"`
	ChallengeFile    string `json:"challengeFile,omitempty" yaml:"challengeFile,omitempty"`
	RateLimitFile    string `json:"rateLimitFile,omitempty" yaml:"rateLimitFile,omitempty"`
	UnavailableFile  string `json:"unavailableFile,omitempty" yaml:"unavailableFile,omitempty"`
	MaximumFileBytes int64  `json:"maximumFileBytes,omitempty" yaml:"maximumFileBytes,omitempty"`
	ReloadInterval   string `json:"reloadInterval,omitempty" yaml:"reloadInterval,omitempty"`
	DefaultFormat    string `json:"defaultFormat,omitempty" yaml:"defaultFormat,omitempty"`
	AllowSymlinks    bool   `json:"allowSymlinks,omitempty" yaml:"allowSymlinks,omitempty"`
}

type CacheConfig struct {
	MaximumEntries int    `json:"maximumEntries,omitempty" yaml:"maximumEntries,omitempty"`
	MaximumTTL     string `json:"maximumTTL,omitempty" yaml:"maximumTTL,omitempty"`
}

type CircuitBreakerConfig struct {
	FailureThreshold int    `json:"failureThreshold,omitempty" yaml:"failureThreshold,omitempty"`
	OpenDuration     string `json:"openDuration,omitempty" yaml:"openDuration,omitempty"`
}

type ChallengeConfig struct {
	PathPrefix       string `json:"pathPrefix,omitempty" yaml:"pathPrefix,omitempty"`
	MaximumBodyBytes int64  `json:"maximumBodyBytes,omitempty" yaml:"maximumBodyBytes,omitempty"`
	RequestTimeout   string `json:"requestTimeout,omitempty" yaml:"requestTimeout,omitempty"`
}

// CreateConfig creates secure, bounded defaults.
func CreateConfig() *Config {
	return &Config{
		Agent: AgentConfig{
			Endpoint:       "http://sokol-edge-agent:8080",
			TokenFile:      "/run/secrets/sokol-plugin-token",
			ConnectTimeout: "100ms",
			RequestTimeout: "500ms",
		},
		FailureMode: FailureModeConfig{
			AgentUnavailable:  "allow",
			MalformedResponse: "allow",
			ExplicitLocalDeny: "deny",
		},
		ClientIP: ClientIPConfig{
			Strategy:         "forwarded",
			CloudflareHeader: "CF-Connecting-IP",
			BunnyHeader:      "X-Real-IP",
		},
		RequestBody: RequestBodyConfig{
			Enabled:        false,
			MaximumBytes:   1 << 20,
			OversizeAction: "headers_only",
			ContentTypes: []string{
				"application/json",
				"application/x-www-form-urlencoded",
				"application/xml",
				"text/xml",
			},
		},
		Request: RequestConfig{
			Headers: []string{
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
			},
			Cookies: []string{"__Host-sokol_trust"},
		},
		Responses: ResponsesConfig{
			Root:             "/etc/traefik/sokol",
			BlockFile:        "block.html",
			ChallengeFile:    "challenge.html",
			RateLimitFile:    "rate-limit.html",
			UnavailableFile:  "unavailable.html",
			MaximumFileBytes: 512 << 10,
			ReloadInterval:   "30s",
			DefaultFormat:    "html",
			AllowSymlinks:    false,
		},
		Cache: CacheConfig{
			MaximumEntries: 4096,
			MaximumTTL:     "1s",
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 3,
			OpenDuration:     "5s",
		},
		Challenge: ChallengeConfig{
			PathPrefix:       "/.sokol",
			MaximumBodyBytes: 64 << 10,
			RequestTimeout:   "2s",
		},
	}
}

type runtimeConfig struct {
	connectTimeout   time.Duration
	requestTimeout   time.Duration
	challengeTimeout time.Duration
	reloadInterval   time.Duration
	maximumCacheTTL  time.Duration
	openDuration     time.Duration
	trusted          []*net.IPNet
	responseRoot     string
}

// Middleware is the request-scoped Traefik integration.
type Middleware struct {
	next            http.Handler
	name            string
	config          *Config
	runtime         runtimeConfig
	agent           *agentClient
	pages           *pageStore
	cache           *decisionCache
	breaker         *circuitBreaker
	selectedHeads   []string
	selectedCookies map[string]struct{}
	providers       *providerRangeStore
}

// New constructs the middleware using Traefik's plugin contract.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("next handler is required")
	}
	if config == nil {
		return nil, errors.New("configuration is required")
	}
	runtime, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	token, err := readTokenFile(config.Agent.TokenFile)
	if err != nil {
		return nil, err
	}
	client, err := newAgentClient(
		config.Agent.Endpoint,
		token,
		runtime.connectTimeout,
		runtime.requestTimeout,
		runtime.challengeTimeout,
	)
	if err != nil {
		return nil, err
	}
	headers := make([]string, 0, len(config.Request.Headers))
	for _, header := range config.Request.Headers {
		headers = append(headers, http.CanonicalHeaderKey(header))
	}
	cookies := make(map[string]struct{}, len(config.Request.Cookies))
	for _, cookie := range config.Request.Cookies {
		cookies[cookie] = struct{}{}
	}
	middleware := &Middleware{
		next:            next,
		name:            name,
		config:          config,
		runtime:         runtime,
		agent:           client,
		pages:           newPageStore(config.Responses, runtime.responseRoot, runtime.reloadInterval),
		cache:           newDecisionCache(config.Cache.MaximumEntries, runtime.maximumCacheTTL),
		breaker:         newCircuitBreaker(config.CircuitBreaker.FailureThreshold, runtime.openDuration),
		selectedHeads:   headers,
		selectedCookies: cookies,
		providers:       defaultProviderStore,
	}
	startDefaultProviderRefresh(ctx)
	return middleware, nil
}

func validateConfig(config *Config) (runtimeConfig, error) {
	var result runtimeConfig
	var problems []string
	parseDuration := func(name, value string, minimum, maximum time.Duration) time.Duration {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < minimum || parsed > maximum {
			problems = append(problems, fmt.Sprintf("%s must be between %s and %s", name, minimum, maximum))
			return 0
		}
		return parsed
	}
	result.connectTimeout = parseDuration("agent.connectTimeout", config.Agent.ConnectTimeout, time.Millisecond, time.Second)
	result.requestTimeout = parseDuration("agent.requestTimeout", config.Agent.RequestTimeout, time.Millisecond, maximumAgentTimeout)
	result.challengeTimeout = parseDuration(
		"challenge.requestTimeout",
		config.Challenge.RequestTimeout,
		time.Millisecond,
		maximumChallengeTimeout,
	)
	if result.requestTimeout > 0 && result.connectTimeout > result.requestTimeout {
		problems = append(problems, "agent.connectTimeout must not exceed agent.requestTimeout")
	}
	if result.challengeTimeout > 0 && result.connectTimeout > result.challengeTimeout {
		problems = append(problems, "agent.connectTimeout must not exceed challenge.requestTimeout")
	}
	result.reloadInterval = parseDuration("responses.reloadInterval", config.Responses.ReloadInterval, time.Second, time.Hour)
	result.maximumCacheTTL = parseDuration("cache.maximumTTL", config.Cache.MaximumTTL, 0, maximumCacheTTL)
	result.openDuration = parseDuration("circuitBreaker.openDuration", config.CircuitBreaker.OpenDuration, 100*time.Millisecond, time.Minute)

	if err := validateAgentEndpoint(config.Agent.Endpoint); err != nil {
		problems = append(problems, err.Error())
	}
	if !filepath.IsAbs(config.Agent.TokenFile) {
		problems = append(problems, "agent.tokenFile must be absolute")
	}
	for name, value := range map[string]string{
		"failureMode.agentUnavailable":  config.FailureMode.AgentUnavailable,
		"failureMode.malformedResponse": config.FailureMode.MalformedResponse,
	} {
		if value != "allow" && value != "deny" {
			problems = append(problems, name+" must be allow or deny")
		}
	}
	if config.FailureMode.ExplicitLocalDeny != "allow" && config.FailureMode.ExplicitLocalDeny != "deny" {
		problems = append(problems, "failureMode.explicitLocalDeny must be allow or deny")
	}
	switch config.ClientIP.Strategy {
	case "direct", "forwarded", "cloudflare", "bunny":
	default:
		problems = append(problems, "clientIP.strategy must be direct, forwarded, cloudflare, or bunny")
	}
	if !validHeaderName(config.ClientIP.CloudflareHeader) || !validHeaderName(config.ClientIP.BunnyHeader) {
		problems = append(problems, "client IP provider headers must be valid HTTP header names")
	}
	parseNetworks := func(name string, values []string) []*net.IPNet {
		var networks []*net.IPNet
		for _, value := range values {
			_, network, err := net.ParseCIDR(strings.TrimSpace(value))
			if err != nil {
				problems = append(problems, name+" contains an invalid CIDR")
				continue
			}
			networks = append(networks, network)
		}
		if len(values) > 128 {
			problems = append(problems, name+" must not exceed 128 CIDRs")
		}
		return networks
	}
	result.trusted = parseNetworks("trustedProxies", config.TrustedProxies)
	if config.RequestBody.MaximumBytes < 1 || config.RequestBody.MaximumBytes > maximumBodyBytes {
		problems = append(problems, "requestBody.maximumBytes must be between 1 byte and 1 MiB")
	}
	if config.RequestBody.OversizeAction != "headers_only" && config.RequestBody.OversizeAction != "reject" {
		problems = append(problems, "requestBody.oversizeAction must be headers_only or reject")
	}
	for _, contentType := range config.RequestBody.ContentTypes {
		if !validContentTypePattern(contentType) {
			problems = append(problems, "requestBody.contentTypes contains an invalid media type")
		}
	}
	if len(config.RequestBody.ContentTypes) > 32 {
		problems = append(problems, "requestBody.contentTypes must not exceed 32 entries")
	}
	for _, prefix := range config.RequestBody.BypassPathPrefix {
		if !validPathPrefix(prefix) {
			problems = append(problems, "requestBody.bypassPathPrefixes contains an invalid path prefix")
		}
	}
	if len(config.RequestBody.BypassPathPrefix) > 32 {
		problems = append(problems, "requestBody.bypassPathPrefixes must not exceed 32 entries")
	}
	for _, header := range config.Request.Headers {
		if !validHeaderName(header) || sensitiveRequestHeader(header) {
			problems = append(problems, "request.headers contains an invalid or sensitive header")
		}
	}
	if len(config.Request.Headers) > 64 {
		problems = append(problems, "request.headers must not exceed 64 entries")
	}
	for _, cookie := range config.Request.Cookies {
		if !validCookieName(cookie) {
			problems = append(problems, "request.cookies contains an invalid cookie name")
		}
	}
	if len(config.Request.Cookies) > 64 {
		problems = append(problems, "request.cookies must not exceed 64 entries")
	}
	root, err := filepath.Abs(filepath.Clean(config.Responses.Root))
	if err != nil || !filepath.IsAbs(config.Responses.Root) {
		problems = append(problems, "responses.root must be an absolute path")
	} else {
		result.responseRoot = root
	}
	for name, value := range map[string]string{
		"responses.blockFile":       config.Responses.BlockFile,
		"responses.challengeFile":   config.Responses.ChallengeFile,
		"responses.rateLimitFile":   config.Responses.RateLimitFile,
		"responses.unavailableFile": config.Responses.UnavailableFile,
	} {
		if err := validateRelativePagePath(result.responseRoot, value); err != nil {
			problems = append(problems, name+" must remain inside responses.root")
		}
	}
	if config.Responses.MaximumFileBytes < 1 || config.Responses.MaximumFileBytes > 4<<20 {
		problems = append(problems, "responses.maximumFileBytes must be between 1 byte and 4 MiB")
	}
	if config.Responses.DefaultFormat != "html" && config.Responses.DefaultFormat != "json" {
		problems = append(problems, "responses.defaultFormat must be html or json")
	}
	if config.Cache.MaximumEntries < 0 || config.Cache.MaximumEntries > 10000 {
		problems = append(problems, "cache.maximumEntries must be between 0 and 10000")
	}
	if config.CircuitBreaker.FailureThreshold < 1 || config.CircuitBreaker.FailureThreshold > 100 {
		problems = append(problems, "circuitBreaker.failureThreshold must be between 1 and 100")
	}
	if !validPathPrefix(config.Challenge.PathPrefix) ||
		config.Challenge.PathPrefix == "/" ||
		strings.HasSuffix(config.Challenge.PathPrefix, "/") {
		problems = append(problems, "challenge.pathPrefix must be a non-root normalized path without a trailing slash")
	}
	if config.Challenge.MaximumBodyBytes < 1024 || config.Challenge.MaximumBodyBytes > 256<<10 {
		problems = append(problems, "challenge.maximumBodyBytes must be between 1 KiB and 256 KiB")
	}
	if len(config.ResourceHint) > 128 {
		problems = append(problems, "resourceHint must not exceed 128 characters")
	}
	if len(problems) != 0 {
		return runtimeConfig{}, errors.New(strings.Join(problems, "; "))
	}
	return result, nil
}

func validateAgentEndpoint(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return errors.New("agent.endpoint is invalid")
	}
	if parsed.Scheme == "unix" {
		if parsed.Host != "" || !filepath.IsAbs(parsed.Path) || parsed.RawQuery != "" || parsed.Fragment != "" {
			return errors.New("agent.endpoint Unix socket must be an absolute unix:/// path")
		}
		return nil
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("agent.endpoint must use http, https, or unix")
	}
	if parsed.User != nil || parsed.Host == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("agent.endpoint must contain only a local origin")
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if !localAgentIP(ip) {
			return errors.New("agent.endpoint IP must be local, private, or link-local")
		}
		return nil
	}
	if host != "localhost" && strings.Contains(host, ".") {
		return errors.New("agent.endpoint DNS name must be localhost or a single-label private service name")
	}
	return nil
}

func localAgentIP(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func readTokenFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("read agent token metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o007 != 0 {
		return "", errors.New("agent token must be a regular file inaccessible to other users")
	}
	if info.Size() < 32 || info.Size() > 1025 {
		return "", errors.New("agent token file must contain 32..1025 bytes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read agent token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || len(token) > 1024 || strings.ContainsAny(token, "\r\n") {
		return "", errors.New("agent token must contain 32..1024 characters on one line")
	}
	return token, nil
}

func validHeaderName(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", character) {
			return false
		}
	}
	return true
}

func sensitiveRequestHeader(value string) bool {
	switch strings.ToLower(value) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie":
		return true
	default:
		return false
	}
}

func validCookieName(value string) bool {
	return validHeaderName(value) && len(value) <= 128
}

func validContentTypePattern(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	parts := strings.Split(value, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
		!strings.ContainsAny(value, " \t\r\n;") &&
		(parts[1] == "*" || !strings.Contains(parts[1], "*"))
}

func validPathPrefix(value string) bool {
	return strings.HasPrefix(value, "/") && len(value) <= 8192 && !strings.ContainsAny(value, "\x00\r\n")
}

func validateRelativePagePath(root, name string) error {
	if root == "" || name == "" || filepath.IsAbs(name) {
		return errors.New("invalid page path")
	}
	candidate := filepath.Clean(filepath.Join(root, name))
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("page escapes root")
	}
	return nil
}
