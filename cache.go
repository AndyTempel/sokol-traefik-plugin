package sokol_traefik_plugin

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

type decisionCacheEntry struct {
	response  evaluationResponse
	expiresAt time.Time
	createdAt time.Time
}

type decisionCache struct {
	mu             sync.Mutex
	entries        map[string]decisionCacheEntry
	maximumEntries int
	maximumTTL     time.Duration
}

func newDecisionCache(maximumEntries int, maximumTTL time.Duration) *decisionCache {
	return &decisionCache{
		entries:        make(map[string]decisionCacheEntry),
		maximumEntries: maximumEntries,
		maximumTTL:     maximumTTL,
	}
}

func (c *decisionCache) get(key, requestID string, now time.Time) (evaluationResponse, bool) {
	if c.maximumEntries == 0 || c.maximumTTL == 0 {
		return evaluationResponse{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return evaluationResponse{}, false
	}
	if !now.Before(entry.expiresAt) {
		delete(c.entries, key)
		return evaluationResponse{}, false
	}
	entry.response.RequestID = requestID
	return entry.response, true
}

func (c *decisionCache) put(key string, response evaluationResponse, now time.Time) {
	if c.maximumEntries == 0 || c.maximumTTL == 0 || response.CacheTTLMS <= 0 ||
		response.Decision == "challenge" || response.ChallengeToken != "" {
		return
	}
	ttl := time.Duration(response.CacheTTLMS) * time.Millisecond
	if ttl > c.maximumTTL {
		ttl = c.maximumTTL
	}
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for cacheKey, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			delete(c.entries, cacheKey)
		}
	}
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maximumEntries {
		oldestKey := ""
		var oldest time.Time
		for cacheKey, entry := range c.entries {
			if oldestKey == "" || entry.createdAt.Before(oldest) {
				oldestKey = cacheKey
				oldest = entry.createdAt
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[key] = decisionCacheEntry{
		response: response, expiresAt: now.Add(ttl), createdAt: now,
	}
}

func evaluationCacheKey(request evaluationRequest) string {
	hash := sha256.New()
	writeHashPart(hash, request.ClientIP)
	writeHashPart(hash, request.Method)
	writeHashPart(hash, request.Scheme)
	writeHashPart(hash, request.Host)
	writeHashPart(hash, request.Path)
	writeHashPart(hash, request.Query)
	writeHashPart(hash, request.ProtocolType)
	writeHashPart(hash, request.HTTPVersion)
	writeHashPart(hash, request.ResourceHint)
	if request.BodyTruncated {
		writeHashPart(hash, "body-truncated")
	}
	writeStringMap(hash, request.Headers)
	writeStringMap(hash, request.Cookies)
	if len(request.Body) != 0 {
		bodyHash := sha256.Sum256(request.Body)
		writeHashPart(hash, hex.EncodeToString(bodyHash[:]))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type stringWriter interface {
	Write([]byte) (int, error)
}

func writeHashPart(writer stringWriter, value string) {
	_, _ = writer.Write([]byte(value))
	_, _ = writer.Write([]byte{0})
}

func writeStringMap(writer stringWriter, values map[string]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		writeHashPart(writer, strings.ToLower(key))
		writeHashPart(writer, values[key])
	}
}

type circuitBreaker struct {
	mu               sync.Mutex
	failureThreshold int
	openDuration     time.Duration
	failures         int
	openUntil        time.Time
	probe            bool
}

func newCircuitBreaker(failureThreshold int, openDuration time.Duration) *circuitBreaker {
	return &circuitBreaker{failureThreshold: failureThreshold, openDuration: openDuration}
}

func (c *circuitBreaker) allow(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.openUntil.IsZero() {
		return true
	}
	if now.Before(c.openUntil) {
		return false
	}
	if c.probe {
		return false
	}
	c.probe = true
	return true
}

func (c *circuitBreaker) success() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openUntil = time.Time{}
	c.probe = false
}

func (c *circuitBreaker) failure(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.probe || c.failures >= c.failureThreshold {
		c.openUntil = now.Add(c.openDuration)
	}
	c.probe = false
}
