package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func newBaseTransport() *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
}

var httpClient = &http.Client{
	Timeout:   600 * time.Second,
	Transport: newBaseTransport(),
}

var streamHTTPClient = &http.Client{
	Timeout:   0,
	Transport: newBaseTransport(),
}

// ======================== SOCKS5 代理 ========================

type Socks5Proxy struct {
	Addr     string `json:"addr"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Name     string `json:"name,omitempty"`
}

// Billing header regex for stripping Anthropic system message headers
var reBillingHeader = regexp.MustCompile(`(?m)^x-anthropic-billing-header:\s*.*$`)

func socks5Dial(proxy Socks5Proxy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, target string) (net.Conn, error) {
		conn, err := net.DialTimeout("tcp", proxy.Addr, 10*time.Second)
		if err != nil {
			return nil, fmt.Errorf("socks5 connect to %s: %w", proxy.Addr, err)
		}
		deadline := time.Now().Add(15 * time.Second)
		conn.SetDeadline(deadline)

		// 认证方法协商
		auth := byte(0x00) // no auth
		if proxy.Username != "" {
			auth = 0x02 // username/password
		}
		if _, err := conn.Write([]byte{0x05, 0x01, auth}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 handshake write: %w", err)
		}
		buf := make([]byte, 2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 handshake read: %w", err)
		}
		if buf[0] != 0x05 {
			conn.Close()
			return nil, fmt.Errorf("socks5: not socks5 protocol")
		}

		// 用户名/密码认证
		if buf[1] == 0x02 {
			if proxy.Username == "" {
				conn.Close()
				return nil, fmt.Errorf("socks5: server requires auth but no credentials")
			}
			ulen := len(proxy.Username)
			plen := len(proxy.Password)
			authBuf := make([]byte, 3+ulen+plen)
			authBuf[0] = 0x01
			authBuf[1] = byte(ulen)
			copy(authBuf[2:], proxy.Username)
			authBuf[2+ulen] = byte(plen)
			copy(authBuf[3+ulen:], proxy.Password)
			if _, err := conn.Write(authBuf); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth write: %w", err)
			}
			authResp := make([]byte, 2)
			if _, err := io.ReadFull(conn, authResp); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5 auth read: %w", err)
			}
			if authResp[1] != 0x00 {
				conn.Close()
				return nil, fmt.Errorf("socks5: auth failed")
			}
		} else if buf[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: unsupported auth method 0x%02x", buf[1])
		}

		// CONNECT 请求
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5: invalid target %s: %w", target, err)
		}
		port := 0
		fmt.Sscanf(portStr, "%d", &port)

		req := []byte{0x05, 0x01, 0x00} // VER, CMD=CONNECT, RSV
		ip := net.ParseIP(host)
		if ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				req = append(req, 0x01) // IPv4
				req = append(req, ip4...)
			} else {
				req = append(req, 0x04) // IPv6
				req = append(req, ip.To16()...)
			}
		} else {
			if len(host) > 255 {
				conn.Close()
				return nil, fmt.Errorf("socks5: hostname too long")
			}
			req = append(req, 0x03) // Domain
			req = append(req, byte(len(host)))
			req = append(req, []byte(host)...)
		}
		req = append(req, byte(port>>8), byte(port))

		if _, err := conn.Write(req); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect write: %w", err)
		}

		// 读取响应
		resp := make([]byte, 4)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 connect read: %w", err)
		}
		if resp[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: connect failed, status 0x%02x", resp[1])
		}

		// 读取绑定地址
		switch resp[3] {
		case 0x01: // IPv4
			if _, err := io.ReadFull(conn, make([]byte, 4+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind ipv4: %w", err)
			}
		case 0x03: // Domain
			dlen := make([]byte, 1)
			if _, err := io.ReadFull(conn, dlen); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind domain len: %w", err)
			}
			if _, err := io.ReadFull(conn, make([]byte, int(dlen[0])+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind domain: %w", err)
			}
		case 0x04: // IPv6
			if _, err := io.ReadFull(conn, make([]byte, 16+2)); err != nil {
				conn.Close()
				return nil, fmt.Errorf("socks5: read bind ipv6: %w", err)
			}
		default:
			conn.Close()
			return nil, fmt.Errorf("socks5: unknown address type 0x%02x", resp[3])
		}

		conn.SetDeadline(time.Time{})
		return conn, nil
	}
}

var (
	socks5Proxies []Socks5Proxy
	activeSocks5  string // 启用的代理 Addr；空表示直连；特殊值表示轮询/429 切换
	socks5Mu      sync.RWMutex
)

const (
	socks5RR                      = "__round_robin__"
	socks5RateLimitSwitch         = "__rate_limit_switch__"
	socks5RateLimitSwitchNoDirect = "__rate_limit_switch_no_direct__"
)

var (
	socks5RRIndex        uint32
	socks5RateLimitIndex uint32 // 0 表示直连，1..n 表示 socks5Proxies[n-1]
	socks5LastRRLabel    string // 最近一次轮询选中的代理标签
)

var (
	socks5Client           *http.Client // 缓存的 SOCKS5 非流式客户端
	socks5ClientAddr       string       // 缓存对应的代理地址
	socks5StreamClient     *http.Client // 缓存的 SOCKS5 流式客户端
	socks5StreamClientAddr string       // 缓存对应的代理地址
)

func getHTTPClient(stream bool) *http.Client {
	socks5Mu.Lock()
	defer socks5Mu.Unlock()

	if activeSocks5 == "" {
		if stream {
			return streamHTTPClient
		}
		return httpClient
	}

	var proxy Socks5Proxy
	var useRR bool
	selectedAddr := activeSocks5
	cachedClient := socks5Client
	cachedClientAddr := socks5ClientAddr
	if stream {
		cachedClient = socks5StreamClient
		cachedClientAddr = socks5StreamClientAddr
	}

	if activeSocks5 == socks5RR {
		if len(socks5Proxies) == 0 {
			if stream {
				return streamHTTPClient
			}
			return httpClient
		}
		idx := atomic.AddUint32(&socks5RRIndex, 1) % uint32(len(socks5Proxies))
		proxy = socks5Proxies[idx]
		useRR = true
		selectedAddr = proxy.Addr
		socks5LastRRLabel = socks5ProxyLabel(proxy)
	} else if activeSocks5 == socks5RateLimitSwitch || activeSocks5 == socks5RateLimitSwitchNoDirect {
		var ok bool
		proxy, ok = currentRateLimitProxyLocked(activeSocks5 == socks5RateLimitSwitch)
		if !ok {
			if stream {
				return streamHTTPClient
			}
			return httpClient
		}
		selectedAddr = proxy.Addr
		// Rate-limit mode: always rebuild client, don't cache
	} else {
		if cachedClient != nil && cachedClientAddr == selectedAddr {
			return cachedClient
		}

		var found bool
		for i := range socks5Proxies {
			if socks5Proxies[i].Addr == activeSocks5 {
				proxy = socks5Proxies[i]
				found = true
				break
			}
		}
		if !found {
			if stream {
				return streamHTTPClient
			}
			return httpClient
		}
	}

	// Rate-limit mode: always rebuild client, don't use cache
	if activeSocks5 == socks5RateLimitSwitch || activeSocks5 == socks5RateLimitSwitchNoDirect {
		// skip cache check
	} else if !useRR && cachedClient != nil && cachedClientAddr == selectedAddr {
		return cachedClient
	}

	dial := socks5Dial(proxy)
	client := &http.Client{
		Timeout: map[bool]time.Duration{true: 0, false: 600 * time.Second}[stream],
		Transport: &http.Transport{
			DialContext:         dial,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Only cache for non-rate-limit modes
	if activeSocks5 != socks5RateLimitSwitch && activeSocks5 != socks5RateLimitSwitchNoDirect && !useRR {
		if stream {
			socks5StreamClient = client
			socks5StreamClientAddr = selectedAddr
		} else {
			socks5Client = client
			socks5ClientAddr = selectedAddr
		}
	}
	return client
}

func currentRateLimitProxyLocked(includeDirect bool) (Socks5Proxy, bool) {
	total := len(socks5Proxies)
	if includeDirect {
		total++
	}
	if total <= 0 {
		return Socks5Proxy{}, false
	}
	idx := int(atomic.LoadUint32(&socks5RateLimitIndex)) % total
	if includeDirect && idx == 0 {
		return Socks5Proxy{}, false
	}
	if includeDirect {
		return socks5Proxies[idx-1], true
	}
	return socks5Proxies[idx], true
}

func socks5ProxyLabel(p Socks5Proxy) string {
	if p.Name != "" {
		return p.Name + " (" + p.Addr + ")"
	}
	return p.Addr
}

func socks5ExitLabelLocked(idx int, includeDirect bool) string {
	if includeDirect && idx <= 0 {
		return "direct"
	}
	proxyIdx := idx
	if includeDirect {
		proxyIdx = idx - 1
	}
	if proxyIdx < 0 || proxyIdx >= len(socks5Proxies) {
		return "direct"
	}
	proxy := socks5Proxies[proxyIdx]
	if proxy.Name != "" {
		return proxy.Name + " (" + proxy.Addr + ")"
	}
	return proxy.Addr
}

func currentSocks5ExitLabel() string {
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	// 轮询模式：返回最近一次轮询选中的代理标签
	if activeSocks5 == socks5RR {
		if socks5LastRRLabel != "" {
			return socks5LastRRLabel
		}
		if len(socks5Proxies) == 0 {
			return "direct"
		}
		return socks5ProxyLabel(socks5Proxies[0])
	}
	includeDirect := activeSocks5 == socks5RateLimitSwitch
	total := len(socks5Proxies)
	if includeDirect {
		total++
	}
	if total <= 0 {
		return "direct"
	}
	idx := int(atomic.LoadUint32(&socks5RateLimitIndex)) % total
	return socks5ExitLabelLocked(idx, includeDirect)
}

func socks5RateLimitAttemptCount() int {
	socks5Mu.RLock()
	defer socks5Mu.RUnlock()
	switch activeSocks5 {
	case socks5RateLimitSwitch:
		return len(socks5Proxies) + 1
	case socks5RateLimitSwitchNoDirect:
		if len(socks5Proxies) == 0 {
			return 1
		}
		return len(socks5Proxies)
	default:
		return 1
	}
}

func rotateSocks5OnRateLimit() {
	socks5Mu.Lock()
	defer socks5Mu.Unlock()
	includeDirect := activeSocks5 == socks5RateLimitSwitch
	if activeSocks5 != socks5RateLimitSwitch && activeSocks5 != socks5RateLimitSwitchNoDirect {
		return
	}
	total := len(socks5Proxies)
	if includeDirect {
		total++
	}
	if total <= 1 {
		if includeDirect {
			log.Printf("[rate-limit proxy switch] upstream 429, only direct exit available")
		} else {
			log.Printf("[rate-limit proxy switch] upstream 429, no SOCKS5 exit available")
		}
		return
	}
	oldIdx := int(atomic.LoadUint32(&socks5RateLimitIndex)) % total
	nextIdx := (oldIdx + 1) % total
	atomic.StoreUint32(&socks5RateLimitIndex, uint32(nextIdx))
	socks5Client = nil
	socks5ClientAddr = ""
	log.Printf("[rate-limit proxy switch] upstream 429: %s -> %s", socks5ExitLabelLocked(oldIdx, includeDirect), socks5ExitLabelLocked(nextIdx, includeDirect))
}

// ======================== 随机 ID ========================

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = letters[b[i]%byte(len(letters))]
	}
	return string(b)
}

func randomHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = hex[b[i]%byte(len(hex))]
	}
	return string(b)
}

// ======================== OpenCode 会话 ========================

var (
	upstreamCfg         *UpstreamConfig
	upstreamCfgs        = map[string]*UpstreamConfig{}
	defaultUpstreamName string
	requestCount        atomic.Int64
)

// ======================== 模型 ========================

type ModelInfo struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

var (
	modelsCache  []ModelInfo
	modelMu      sync.RWMutex
	modelsLoaded bool
)

var (
	upstreamKeyCursorMu     sync.Mutex
	upstreamKeyCursor       = map[string]int{}
	upstreamModelsKeyCursor = map[string]int{}
)

func splitUpstreamAPIKeys(raw string) []string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := map[string]struct{}{}
	keys := make([]string, 0, strings.Count(raw, "\n")+1)
	for _, line := range strings.Split(raw, "\n") {
		key := strings.TrimSpace(line)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	return keys
}

func getUpstreamAPIKeys(upstream *UpstreamConfig) []string {
	if upstream == nil {
		return nil
	}
	return splitUpstreamAPIKeys(upstream.APIKey)
}

func nextUpstreamAPIKeyIndex(name string, total int) int {
	if total <= 1 {
		return 0
	}
	resolvedName := effectiveUpstreamName(name)
	upstreamKeyCursorMu.Lock()
	defer upstreamKeyCursorMu.Unlock()
	idx := upstreamKeyCursor[resolvedName] % total
	upstreamKeyCursor[resolvedName] = (idx + 1) % total
	return idx
}

func nextUpstreamModelsKeyIndex(name string, total int) int {
	if total <= 1 {
		return 0
	}
	resolvedName := effectiveUpstreamName(name)
	upstreamKeyCursorMu.Lock()
	defer upstreamKeyCursorMu.Unlock()
	idx := upstreamModelsKeyCursor[resolvedName] % total
	upstreamModelsKeyCursor[resolvedName] = (idx + 1) % total
	return idx
}

func selectUpstreamAPIKey(name string, upstream *UpstreamConfig) (string, int, []string) {
	keys := getUpstreamAPIKeys(upstream)
	if len(keys) == 0 {
		return "", -1, nil
	}
	idx := nextUpstreamAPIKeyIndex(name, len(keys))
	return keys[idx], idx, keys
}

func rotateUpstreamAPIKey(keys []string, current int) (string, int) {
	if len(keys) == 0 {
		return "", -1
	}
	if current < 0 {
		current = 0
	}
	next := (current + 1) % len(keys)
	return keys[next], next
}

func formatUpstreamAPIKeySlot(index int, total int) string {
	if index < 0 || total <= 0 {
		return "0/0"
	}
	return fmt.Sprintf("%d/%d", index+1, total)
}

func parseRetryAfterDelay(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(raw); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(raw)
	if err != nil {
		return 0
	}
	delay := time.Until(when)
	if delay < 0 {
		return 0
	}
	return delay
}

func waitForRetry(ctx context.Context, baseDelay time.Duration, retryAfter string) error {
	delay := baseDelay
	if headerDelay := parseRetryAfterDelay(retryAfter); headerDelay > delay {
		delay = headerDelay
	}
	if delay <= 0 {
		delay = time.Second
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextRetryDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return time.Second
	}
	if delay >= 30*time.Second {
		return 30 * time.Second
	}
	delay *= 2
	if delay > 30*time.Second {
		return 30 * time.Second
	}
	return delay
}

func shouldRetryUpstreamStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func cloneUpstreamConfig(cfg *UpstreamConfig) *UpstreamConfig {
	if cfg == nil {
		return nil
	}
	cp := *cfg
	if cfg.CustomModels != nil {
		cp.CustomModels = append([]string(nil), cfg.CustomModels...)
	}
	return &cp
}

func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameUpstreamConfig(a, b *UpstreamConfig) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.BaseURL == b.BaseURL &&
		a.APIKey == b.APIKey &&
		a.APIType == b.APIType &&
		a.ResponsesReasoningFormat == b.ResponsesReasoningFormat &&
		sameStringSlice(a.CustomModels, b.CustomModels)
}

// upstreamsConfigChanged 判断上游连接相关配置是否变化（模型列表依赖这些字段）。
// 默认上游切换、别名、推理映射、代理等不影响上游模型列表。
func upstreamsConfigChanged(oldMap map[string]*UpstreamConfig, newMap map[string]*UpstreamConfig) bool {
	if len(oldMap) != len(newMap) {
		return true
	}
	for name, newCfg := range newMap {
		oldCfg, ok := oldMap[name]
		if !ok || !sameUpstreamConfig(oldCfg, newCfg) {
			return true
		}
	}
	return false
}

func normalizeSingleUpstream(cfg *UpstreamConfig) bool {
	if cfg == nil {
		return false
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.APIKey = strings.TrimSpace(cfg.APIKey)
	if cfg.APIType == "" {
		cfg.APIType = UpstreamOpenAI
	}
	cfg.ResponsesReasoningFormat = strings.TrimSpace(cfg.ResponsesReasoningFormat)
	if len(cfg.CustomModels) > 0 {
		cleaned := make([]string, 0, len(cfg.CustomModels))
		for _, model := range cfg.CustomModels {
			model = strings.TrimSpace(model)
			if model != "" {
				cleaned = append(cleaned, model)
			}
		}
		cfg.CustomModels = cleaned
	}
	return cfg.BaseURL != ""
}

func sortedUpstreamNames(m map[string]*UpstreamConfig) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func effectiveUpstreamName(name string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	return "default"
}

func getConfiguredUpstreams() (map[string]*UpstreamConfig, string) {
	configMu.RLock()
	defer configMu.RUnlock()
	upstreams := make(map[string]*UpstreamConfig, len(upstreamCfgs))
	for name, cfg := range upstreamCfgs {
		upstreams[name] = cloneUpstreamConfig(cfg)
	}
	return upstreams, defaultUpstreamName
}

func resolveUpstream(name string) (string, *UpstreamConfig) {
	configMu.RLock()
	defer configMu.RUnlock()
	resolvedName := strings.TrimSpace(name)
	if resolvedName == "" {
		resolvedName = defaultUpstreamName
	}
	if cfg := cloneUpstreamConfig(upstreamCfgs[resolvedName]); cfg != nil {
		return resolvedName, cfg
	}
	if cfg := cloneUpstreamConfig(upstreamCfgs[defaultUpstreamName]); cfg != nil {
		return defaultUpstreamName, cfg
	}
	for _, fallbackName := range sortedUpstreamNames(upstreamCfgs) {
		if cfg := cloneUpstreamConfig(upstreamCfgs[fallbackName]); cfg != nil {
			return fallbackName, cfg
		}
	}
	return resolvedName, nil
}

func fetchModelsFromUpstream(name string, cfg *UpstreamConfig) ([]ModelInfo, error) {
	if cfg == nil || cfg.BaseURL == "" {
		return []ModelInfo{}, nil
	}
	ownedBy := effectiveUpstreamName(name)
	if len(cfg.CustomModels) > 0 {
		var models []ModelInfo
		now := time.Now().Unix()
		for _, m := range cfg.CustomModels {
			models = append(models, ModelInfo{ID: m, Object: "model", Created: now, OwnedBy: ownedBy})
		}
		return models, nil
	}
	endpoint := getUpstreamModelsEndpoint(cfg)
	apiKeys := getUpstreamAPIKeys(cfg)
	if len(apiKeys) == 0 {
		apiKeys = []string{""}
	}
	start := nextUpstreamModelsKeyIndex(name, len(apiKeys))
	var lastErr error
	for i := 0; i < len(apiKeys); i++ {
		apiKeyIndex := (start + i) % len(apiKeys)
		apiKey := apiKeys[apiKeyIndex]
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}
		if apiKey != "" {
			if cfg.APIType == UpstreamAnthropic {
				req.Header.Set("x-api-key", apiKey)
				req.Header.Set("anthropic-version", "2023-06-01")
				req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
			} else {
				req.Header.Set("Authorization", "Bearer "+apiKey)
			}
		}
		resp, err := getHTTPClient(false).Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var result struct {
				Data []struct {
					ID string `json:"id"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &result); err != nil {
				return nil, err
			}
			var models []ModelInfo
			now := time.Now().Unix()
			for _, m := range result.Data {
				models = append(models, ModelInfo{ID: m.ID, Object: "model", Created: now, OwnedBy: ownedBy})
			}
			return models, nil
		}
		if shouldRetryUpstreamStatus(resp.StatusCode) && len(apiKeys) > 1 {
			lastErr = fmt.Errorf("models endpoint retryable status %d on key %s", resp.StatusCode, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)))
			continue
		}
		lastErr = fmt.Errorf("models endpoint status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		break
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("models endpoint request failed")
	}
	return nil, lastErr
}

func fetchModels() ([]ModelInfo, error) {
	upstreams, _ := getConfiguredUpstreams()
	if len(upstreams) == 0 {
		return []ModelInfo{}, nil
	}
	var merged []ModelInfo
	var errs []string
	for _, name := range sortedUpstreamNames(upstreams) {
		models, err := fetchModelsFromUpstream(name, upstreams[name])
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		merged = append(merged, models...)
	}
	if len(merged) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "; "))
	}
	return merged, nil
}

func getModelIDs() []string {
	modelMu.RLock()
	defer modelMu.RUnlock()
	ids := make([]string, len(modelsCache))
	for i, m := range modelsCache {
		ids[i] = m.ID
	}
	return ids
}

func getAliasModelInfos() []ModelInfo {
	configMu.RLock()
	defer configMu.RUnlock()
	if len(modelAlias) == 0 {
		return []ModelInfo{}
	}
	names := make([]string, 0, len(modelAlias))
	for name := range modelAlias {
		name = strings.TrimSpace(name)
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	now := time.Now().Unix()
	models := make([]ModelInfo, 0, len(names))
	for _, name := range names {
		models = append(models, ModelInfo{
			ID:      name,
			Object:  "model",
			Created: now,
			OwnedBy: "alias",
		})
	}
	return models
}

func groupModelsByUpstream(models []ModelInfo) map[string][]ModelInfo {
	grouped := map[string][]ModelInfo{}
	for _, model := range models {
		name := effectiveUpstreamName(model.OwnedBy)
		grouped[name] = append(grouped[name], model)
	}
	for name := range grouped {
		sort.Slice(grouped[name], func(i, j int) bool {
			return grouped[name][i].ID < grouped[name][j].ID
		})
	}
	return grouped
}

// ======================== 配置 ========================

var (
	port       string
	configPath = "config.json"
	modelAlias = map[string]ModelAlias{}

	reasoningEffortMap = map[string]string{}
	debugMode          bool
	configMu           sync.RWMutex
)

// ======================== 管理面板认证 ========================

var (
	adminPassword string
	sessions      = map[string]struct{}{}
	sessionsMu    sync.Mutex
)

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if adminPassword == "" {
			next(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		sessionsMu.Lock()
		_, ok := sessions[cookie.Value]
		sessionsMu.Unlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if adminPassword == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			renderLoginPage(w, "表单解析失败")
			return
		}
		if r.FormValue("password") != adminPassword {
			renderLoginPage(w, "密码错误")
			return
		}
		token, err := generateToken()
		if err != nil {
			renderLoginPage(w, "创建会话失败")
			return
		}
		sessionsMu.Lock()
		sessions[token] = struct{}{}
		sessionsMu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: token, Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderLoginPage(w, "")
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	cookie, err := r.Cookie("session")
	if err == nil && cookie.Value != "" {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ======================== Token 统计 ========================

type ModelStats struct {
	RequestCount     int64 `json:"request_count"`
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

// DailyStats 单日统计，每天0点自动重置
type DailyStats struct {
	Date          string                 `json:"date"`
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
}

type TokenStatsData struct {
	TotalRequests int64                  `json:"total_requests"`
	Models        map[string]*ModelStats `json:"models"`
	Daily         *DailyStats            `json:"daily,omitempty"`
}

var (
	tokenStats     = &TokenStatsData{Models: map[string]*ModelStats{}, Daily: nil}
	tokenStatsMu   sync.Mutex
	tokenStatsPath = "stats.json"
	statsDate      string // 当前统计日期 YYYY-MM-DD
)

// ======================== 数据模型 ========================

type OpenAIRequest struct {
	Model           string         `json:"model"`
	Messages        []Message      `json:"messages"`
	Stream          bool           `json:"stream"`
	Temperature     *float64       `json:"temperature,omitempty"`
	MaxTokens       int            `json:"max_tokens,omitempty"`
	TopP            *float64       `json:"top_p,omitempty"`
	Thinking        any            `json:"thinking,omitempty"`
	ReasoningEffort string         `json:"reasoning_effort,omitempty"`
	ExtraBody       map[string]any `json:"extra_body,omitempty"`
	StreamOptions   any            `json:"stream_options,omitempty"`
	Tools           []Tool         `json:"tools,omitempty"`
	ToolChoice      any            `json:"tool_choice,omitempty"`
}

type Message struct {
	Role             string     `json:"role,omitempty"`
	Content          any        `json:"content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID       string     `json:"tool_call_id,omitempty"`
	Name             string     `json:"name,omitempty"`
	ReasoningContent *string    `json:"reasoning_content,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type UpstreamType string

const (
	UpstreamOpenAI    UpstreamType = "openai"
	UpstreamAnthropic UpstreamType = "anthropic"
	UpstreamResponses UpstreamType = "openai-responses"
)

type UpstreamConfig struct {
	BaseURL                  string       `json:"base_url"`
	APIKey                   string       `json:"api_key"`
	APIType                  UpstreamType `json:"api_type"`
	CustomModels             []string     `json:"custom_models,omitempty"`
	ResponsesReasoningFormat string       `json:"responses_reasoning_format,omitempty"`
}

type AppConfig struct {
	ModelAlias map[string]ModelAlias `json:"model_alias"`

	ReasoningEffortMap map[string]string          `json:"reasoning_effort_map"`
	Socks5Proxies      []Socks5Proxy              `json:"socks5_proxies,omitempty"`
	ActiveSocks5       string                     `json:"active_socks5,omitempty"`
	Upstream           *UpstreamConfig            `json:"upstream,omitempty"`
	Upstreams          map[string]*UpstreamConfig `json:"upstreams,omitempty"`
	DefaultUpstream    string                     `json:"default_upstream,omitempty"`
}

type ModelAlias struct {
	TargetModel   string `json:"target_model"`
	Upstream      string `json:"upstream,omitempty"`
	WithReasoning bool   `json:"with_reasoning,omitempty"`
}

// ======================== Anthropic Messages API 类型 ========================

type AnthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []AnthropicMessage `json:"messages"`
	System      any                `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Tools       []AnthropicTool    `json:"tools,omitempty"`
	ToolChoice  any                `json:"tool_choice,omitempty"`
	Metadata    any                `json:"metadata,omitempty"`
	Thinking    any                `json:"thinking,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type AnthropicContent struct {
	Type      string `json:"type"`
	Text      string `json:"text,omitempty"`
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`
	ID        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Input     any    `json:"input,omitempty"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   any    `json:"content,omitempty"`
}

type AnthropicTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	InputSchema any    `json:"input_schema"`
}

type AnthropicResponse struct {
	ID           string             `json:"id"`
	Type         string             `json:"type"`
	Role         string             `json:"role"`
	Content      []AnthropicContent `json:"content"`
	Model        string             `json:"model"`
	StopReason   string             `json:"stop_reason"`
	StopSequence *string            `json:"stop_sequence"`
	Usage        *AnthropicUsage    `json:"usage,omitempty"`
}

type AnthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// ======================== Responses API 类型 ========================

type ResponsesAPIRequest struct {
	Model             string          `json:"model"`
	Input             any             `json:"input"`
	Messages          []Message       `json:"messages,omitempty"`
	Instructions      string          `json:"instructions,omitempty"`
	Stream            bool            `json:"stream,omitempty"`
	Temperature       float64         `json:"temperature,omitempty"`
	MaxTokens         int             `json:"max_output_tokens,omitempty"`
	TopP              float64         `json:"top_p,omitempty"`
	FrequencyPenalty  float64         `json:"frequency_penalty,omitempty"`
	PresencePenalty   float64         `json:"presence_penalty,omitempty"`
	Reasoning         ReasonEffort    `json:"reasoning,omitempty"`
	Include           []string        `json:"include,omitempty"`
	Store             *bool           `json:"store,omitempty"`
	Tools             []ResponsesTool `json:"tools,omitempty"`
	ToolChoice        any             `json:"tool_choice,omitempty"`
	ParallelToolCalls *bool           `json:"parallel_tool_calls,omitempty"`
	Stop              any             `json:"stop,omitempty"`
	User              string          `json:"user,omitempty"`
	StreamOptions     any             `json:"stream_options,omitempty"`
	Metadata          any             `json:"metadata,omitempty"`
}

type ResponsesTool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	Parameters  map[string]any  `json:"parameters,omitempty"`
	Function    *ToolFunction   `json:"function,omitempty"`
	Tools       []ResponsesTool `json:"tools,omitempty"`
}

type ResponseToolNameMapping struct {
	Namespace string
	Name      string
}

type ReasonEffort struct {
	Effort string `json:"effort,omitempty"`
}

// ======================== 配置管理 ========================

func loadConfig(path string) AppConfig {
	var cfg AppConfig
	data, err := os.ReadFile(path)
	if err != nil {
		normalizeConfig(&cfg)
		return cfg
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("警告: 配置文件解析失败: %v", err)
	}
	normalizeConfig(&cfg)
	return cfg
}

func normalizeConfig(cfg *AppConfig) {
	if cfg.ModelAlias == nil {
		cfg.ModelAlias = map[string]ModelAlias{}
	}
	for key, alias := range cfg.ModelAlias {
		trimmedKey := strings.TrimSpace(key)
		alias.TargetModel = strings.TrimSpace(alias.TargetModel)
		alias.Upstream = strings.TrimSpace(alias.Upstream)
		if trimmedKey == "" {
			delete(cfg.ModelAlias, key)
			continue
		}
		if trimmedKey != key {
			delete(cfg.ModelAlias, key)
		}
		cfg.ModelAlias[trimmedKey] = alias
	}

	if cfg.ReasoningEffortMap == nil {
		cfg.ReasoningEffortMap = map[string]string{}
	}
	if cfg.Upstreams == nil {
		cfg.Upstreams = map[string]*UpstreamConfig{}
	}
	legacy := cloneUpstreamConfig(cfg.Upstream)
	legacyValid := normalizeSingleUpstream(legacy)
	normalizedUpstreams := make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		trimmedName := strings.TrimSpace(name)
		copied := cloneUpstreamConfig(upstream)
		if trimmedName == "" || !normalizeSingleUpstream(copied) {
			continue
		}
		normalizedUpstreams[trimmedName] = copied
	}
	cfg.Upstreams = normalizedUpstreams
	cfg.DefaultUpstream = strings.TrimSpace(cfg.DefaultUpstream)
	if len(cfg.Upstreams) == 0 && legacyValid {
		cfg.Upstreams["default"] = legacy
		if cfg.DefaultUpstream == "" {
			cfg.DefaultUpstream = "default"
		}
	}
	if len(cfg.Upstreams) == 0 {
		cfg.DefaultUpstream = ""
		cfg.Upstream = nil
		return
	}
	if cfg.DefaultUpstream == "" || cfg.Upstreams[cfg.DefaultUpstream] == nil {
		names := sortedUpstreamNames(cfg.Upstreams)
		if len(names) > 0 {
			cfg.DefaultUpstream = names[0]
		}
	}
	cfg.Upstream = nil
}

func saveConfig(path string, cfg AppConfig) error {
	normalizeConfig(&cfg)
	cfg.Upstream = nil
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func applyConfig(cfg AppConfig) bool {
	configMu.Lock()
	defer configMu.Unlock()
	if cfg.ModelAlias != nil {
		modelAlias = cfg.ModelAlias
	}

	if cfg.ReasoningEffortMap != nil {
		reasoningEffortMap = cfg.ReasoningEffortMap
	}
	upstreamsChanged := upstreamsConfigChanged(upstreamCfgs, cfg.Upstreams)
	upstreamCfgs = make(map[string]*UpstreamConfig, len(cfg.Upstreams))
	for name, upstream := range cfg.Upstreams {
		upstreamCfgs[name] = cloneUpstreamConfig(upstream)
	}
	defaultUpstreamName = strings.TrimSpace(cfg.DefaultUpstream)
	if defaultUpstreamName == "" && len(upstreamCfgs) > 0 {
		names := sortedUpstreamNames(upstreamCfgs)
		if len(names) > 0 {
			defaultUpstreamName = names[0]
		}
	}
	upstreamCfg = cloneUpstreamConfig(upstreamCfgs[defaultUpstreamName])
	// 仅上游连接配置变化时重置模型缓存（别名/推理/代理保存不再清空）
	if upstreamsChanged {
		modelMu.Lock()
		modelsLoaded = false
		modelsCache = nil
		modelMu.Unlock()
	}

	socks5Mu.Lock()
	proxiesUpdated := false
	if cfg.Socks5Proxies != nil {
		socks5Proxies = cfg.Socks5Proxies
		proxiesUpdated = true
	}
	if proxiesUpdated || activeSocks5 != cfg.ActiveSocks5 {
		activeSocks5 = cfg.ActiveSocks5
		socks5Client = nil
		socks5ClientAddr = ""
		socks5StreamClient = nil
		socks5StreamClientAddr = ""
		atomic.StoreUint32(&socks5RRIndex, 0)
		atomic.StoreUint32(&socks5RateLimitIndex, 0)
	}
	socks5Mu.Unlock()

	return upstreamsChanged
}

func resolveModel(model string) (string, ModelAlias, string, *UpstreamConfig) {
	m := strings.TrimSpace(model)
	alias := ModelAlias{}
	configMu.RLock()
	if found, ok := modelAlias[m]; ok {
		alias = found
	}
	configMu.RUnlock()
	if alias.TargetModel != "" {
		m = alias.TargetModel
	}
	upstreamName, upstream := resolveUpstream(alias.Upstream)
	if m == "" {
		m = strings.TrimSpace(model)
	}
	return m, alias, upstreamName, upstream
}

func resolveModelAlias(model string) (string, ModelAlias) {
	resolvedModel, alias, _, _ := resolveModel(model)
	return resolvedModel, alias
}

func resolveModelName(model string) string {
	name, _, _, _ := resolveModel(model)
	return name
}

func getDefaultUpstreamName() string {
	configMu.RLock()
	defer configMu.RUnlock()
	return defaultUpstreamName
}

func getConfiguredUpstreamCount() int {
	configMu.RLock()
	defer configMu.RUnlock()
	return len(upstreamCfgs)
}

func getDefaultUpstreamConfig() *UpstreamConfig {
	configMu.RLock()
	defer configMu.RUnlock()
	return cloneUpstreamConfig(upstreamCfgs[defaultUpstreamName])
}

func getUpstreamNames() []string {
	configMu.RLock()
	defer configMu.RUnlock()
	return sortedUpstreamNames(upstreamCfgs)
}

func getReasoningEffortMap() map[string]string {
	configMu.RLock()
	defer configMu.RUnlock()
	cp := make(map[string]string, len(reasoningEffortMap))
	for k, v := range reasoningEffortMap {
		cp[k] = v
	}
	return cp
}

// ======================== Token 统计 ========================

func getToday() string {
	return time.Now().Format("2006-01-02")
}

func checkAndResetDailyStats() {
	today := getToday()
	tokenStatsMu.Lock()
	defer tokenStatsMu.Unlock()
	if statsDate == "" {
		statsDate = today
		if tokenStats.Daily == nil || tokenStats.Daily.Date != today {
			tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
		}
		return
	}
	if statsDate != today {
		log.Printf("[统计] 日期变更 %s -> %s，重置每日统计", statsDate, today)
		statsDate = today
		tokenStats.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
}

func loadTokenStats() {
	data, err := os.ReadFile(tokenStatsPath)
	if err != nil {
		checkAndResetDailyStats()
		return
	}
	var st TokenStatsData
	if err := json.Unmarshal(data, &st); err != nil {
		checkAndResetDailyStats()
		return
	}
	tokenStatsMu.Lock()
	if st.Models == nil {
		st.Models = map[string]*ModelStats{}
	}
	today := getToday()
	if st.Daily != nil && st.Daily.Date != today {
		log.Printf("[统计] 每日统计日期 %s 已过期，重置", st.Daily.Date)
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	} else if st.Daily == nil {
		st.Daily = &DailyStats{Date: today, Models: map[string]*ModelStats{}}
	}
	statsDate = today
	tokenStats = &st
	tokenStatsMu.Unlock()
}

func saveTokenStats() {
	tokenStatsMu.Lock()
	data, err := json.MarshalIndent(tokenStats, "", "  ")
	tokenStatsMu.Unlock()
	if err != nil {
		return
	}
	os.WriteFile(tokenStatsPath, data, 0644)
}

func recordTokenUsage(model string, promptTokens, completionTokens, totalTokens int64) {
	checkAndResetDailyStats()
	tokenStatsMu.Lock()
	tokenStats.TotalRequests++
	ms, ok := tokenStats.Models[model]
	if !ok {
		ms = &ModelStats{}
		tokenStats.Models[model] = ms
	}
	ms.RequestCount++
	ms.PromptTokens += promptTokens
	ms.CompletionTokens += completionTokens
	ms.TotalTokens += totalTokens
	if tokenStats.Daily == nil {
		tokenStats.Daily = &DailyStats{Date: getToday(), Models: map[string]*ModelStats{}}
	}
	tokenStats.Daily.TotalRequests++
	dms, ok := tokenStats.Daily.Models[model]
	if !ok {
		dms = &ModelStats{}
		tokenStats.Daily.Models[model] = dms
	}
	dms.RequestCount++
	dms.PromptTokens += promptTokens
	dms.CompletionTokens += completionTokens
	dms.TotalTokens += totalTokens
	tokenStatsMu.Unlock()
	go saveTokenStats()
}

// ======================== Thinking/Reasoning 判断 ========================

func numberFromAny(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}

func reasoningEffortFromThinking(value any) string {
	switch v := value.(type) {
	case map[string]any:
		t, _ := v["type"].(string)
		switch strings.ToLower(t) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			if budget, ok := numberFromAny(v["budget_tokens"]); ok && budget > 0 {
				switch {
				case budget < 4000:
					return "low"
				case budget <= 16000:
					return "medium"
				default:
					return "high"
				}
			}
			return "medium"
		}
	case map[string]string:
		switch strings.ToLower(v["type"]) {
		case "disabled":
			return "none"
		case "adaptive":
			return "xhigh"
		case "enabled":
			return "medium"
		}
	case bool:
		if v {
			return "medium"
		}
		return "none"
	}
	return ""
}

func ensureReasoningEffort(req *OpenAIRequest, alias ModelAlias) {
	if req == nil || req.ReasoningEffort != "" {
		return
	}
	if effort := reasoningEffortFromThinking(req.Thinking); effort != "" {
		if effort != "none" {
			req.ReasoningEffort = effort
		}
		return
	}
	if req.ExtraBody != nil {
		if effort := reasoningEffortFromThinking(req.ExtraBody["thinking"]); effort != "" {
			if effort != "none" {
				req.ReasoningEffort = effort
			}
			return
		}
	}
}

func shouldUseLegacyResponsesReasoningEffort(upstream *UpstreamConfig) bool {
	if upstream == nil {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(upstream.ResponsesReasoningFormat))
	return v == "reasoning_effort" || v == "legacy" || v == "legacy_reasoning_effort"
}

func setResponsesReasoningEffort(req map[string]any, effort string, upstream *UpstreamConfig) {
	if effort == "" || effort == "none" {
		return
	}
	if shouldUseLegacyResponsesReasoningEffort(upstream) {
		req["reasoning_effort"] = effort
		return
	}
	req["reasoning"] = map[string]any{"effort": effort}
}

func mapConfiguredReasoningEffort(effort string) string {
	if effort == "" {
		return ""
	}
	effortMap := getReasoningEffortMap()
	if mapped, ok := effortMap[effort]; ok {
		return mapped
	}
	return effort
}

// ======================== 上游格式转换 ========================

// reasoningEffortToAnthropicThinking maps OpenAI-compatible reasoning_effort
// to Anthropic thinking with a default budget_tokens (required by Anthropic API).
func reasoningEffortToAnthropicThinking(effort string) map[string]any {
	switch strings.ToLower(effort) {
	case "low":
		return map[string]any{"type": "enabled", "budget_tokens": 4000}
	case "medium":
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	case "high":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "xhigh":
		return map[string]any{"type": "enabled", "budget_tokens": 64000}
	case "adaptive":
		return map[string]any{"type": "enabled", "budget_tokens": 32000}
	case "":
		return nil
	default:
		return map[string]any{"type": "enabled", "budget_tokens": 16000}
	}
}

// buildAnthropicThinking picks the Anthropic thinking config from an OpenAI-style
// request body: prefer explicit thinking, fall back to reasoning_effort.
func buildAnthropicThinking(req map[string]any) any {
	if thinking, ok := req["thinking"]; ok {
		if tm, ok := thinking.(map[string]any); ok {
			if t, _ := tm["type"].(string); strings.EqualFold(t, "enabled") {
				if _, has := tm["budget_tokens"]; !has {
					tm["budget_tokens"] = 16000
				}
			}
			return tm
		}
		if tm, ok := thinking.(map[string]string); ok {
			switch strings.ToLower(tm["type"]) {
			case "disabled":
				return nil
			case "enabled":
				return map[string]any{"type": "enabled", "budget_tokens": 16000}
			default:
				return map[string]any{"type": tm["type"]}
			}
		}
		return thinking
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" && re != "none" {
		return reasoningEffortToAnthropicThinking(re)
	}
	return nil
}

// openAIToAnthropicRequest 将 OpenAI Chat 请求转为 Anthropic Messages 格式
func openAIToAnthropicRequest(body []byte) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}

	model, _ := req["model"].(string)
	msgs, _ := req["messages"].([]any)

	var systemTexts []string
	var anthropicMsgs []map[string]any
	handleContent := func(content any, role string) []map[string]any {
		var blocks []map[string]any
		switch c := content.(type) {
		case string:
			if c != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": c})
			}
		case []any:
			for _, item := range c {
				if p, ok := item.(map[string]any); ok {
					switch p["type"] {
					case "text":
						if t, ok := p["text"].(string); ok && t != "" {
							blocks = append(blocks, map[string]any{"type": "text", "text": t})
						}
					case "image_url":
						blocks = append(blocks, convertOpenAIImageToAnthropic(p))
					}
				}
			}
		}
		return blocks
	}

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			if s, ok := content.(string); ok {
				systemTexts = append(systemTexts, s)
			}
			continue
		}

		if role == "assistant" {
			var blocks []map[string]any

			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				blocks = append(blocks, map[string]any{"type": "thinking", "thinking": rc})
			}

			blocks = append(blocks, handleContent(content, role)...)

			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					var args any = map[string]any{}
					if rawArgs, ok := fn["arguments"]; ok && rawArgs != nil {
						switch v := rawArgs.(type) {
						case string:
							if v != "" {
								var parsed any
								if json.Unmarshal([]byte(v), &parsed) == nil {
									args = parsed
								}
							}
						default:
							b, _ := json.Marshal(v)
							var parsed any
							if json.Unmarshal(b, &parsed) == nil {
								args = parsed
							}
						}
					}
					blocks = append(blocks, map[string]any{
						"type": "tool_use", "id": id, "name": name, "input": args,
					})
				}
			}

			if len(blocks) == 0 {
				blocks = append(blocks, map[string]any{"type": "text", "text": ""})
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "assistant", "content": blocks})
			continue
		}

		if role == "tool" {
			toolCallID, _ := msg["tool_call_id"].(string)
			var resultText string
			if s, ok := content.(string); ok {
				resultText = s
			} else {
				b, _ := json.Marshal(content)
				resultText = string(b)
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{
				"role": "user",
				"content": []map[string]any{
					{"type": "tool_result", "tool_use_id": toolCallID, "content": resultText},
				},
			})
			continue
		}

		if role == "user" {
			blocks := handleContent(content, role)
			if len(blocks) == 0 {
				continue
			}
			anthropicMsgs = append(anthropicMsgs, map[string]any{"role": "user", "content": blocks})
		}
	}

	if len(anthropicMsgs) == 0 {
		return body
	}

	anthropicReq := map[string]any{
		"model":      model,
		"messages":   anthropicMsgs,
		"max_tokens": 4096,
	}
	if len(systemTexts) > 0 {
		anthropicReq["system"] = strings.Join(systemTexts, "\n")
	}
	if stream, _ := req["stream"].(bool); stream {
		anthropicReq["stream"] = true
	}
	if temp, _ := req["temperature"].(float64); temp != 0 {
		anthropicReq["temperature"] = temp
	}
	if topP, _ := req["top_p"].(float64); topP != 0 {
		anthropicReq["top_p"] = topP
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		anthropicReq["max_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		anthropicReq["tools"] = convertOpenAIToolsToAnthropic(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		switch v := tc.(type) {
		case string:
			// OpenAI: "auto", "none", "required" -> Anthropic: {type: ...}
			switch v {
			case "auto":
				anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
			case "none":
				anthropicReq["tool_choice"] = map[string]any{"type": "none"}
			case "required":
				anthropicReq["tool_choice"] = map[string]any{"type": "any"}
			default:
				anthropicReq["tool_choice"] = tc
			}
		case map[string]any:
			// OpenAI: {"type": "function", "function": {"name": "xxx"}}
			// Anthropic: {"type": "tool", "name": "xxx"}
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					anthropicReq["tool_choice"] = map[string]any{"type": "tool", "name": name}
				} else {
					anthropicReq["tool_choice"] = map[string]any{"type": "auto"}
				}
			} else {
				anthropicReq["tool_choice"] = tc
			}
		default:
			anthropicReq["tool_choice"] = tc
		}
	}
	if t := buildAnthropicThinking(req); t != nil {
		anthropicReq["thinking"] = t
	}

	result, _ := json.Marshal(anthropicReq)
	return result
}

func convertOpenAIImageToAnthropic(part map[string]any) map[string]any {
	imgURL, _ := part["image_url"].(map[string]any)
	if imgURL == nil {
		return part
	}
	url, _ := imgURL["url"].(string)
	if strings.HasPrefix(url, "data:") {
		parts := strings.SplitN(url, ",", 2)
		if len(parts) == 2 {
			mediaType := strings.TrimPrefix(parts[0], "data:")
			if idx := strings.Index(mediaType, ";"); idx >= 0 {
				mediaType = mediaType[:idx]
			}
			return map[string]any{
				"type": "image",
				"source": map[string]any{
					"type":       "base64",
					"media_type": mediaType,
					"data":       parts[1],
				},
			}
		}
	}
	return map[string]any{
		"type": "image",
		"source": map[string]any{
			"type": "url",
			"url":  url,
		},
	}
}

func convertOpenAIToolsToAnthropic(tools []any) []map[string]any {
	var result []map[string]any
	for _, t := range tools {
		tc, _ := t.(map[string]any)
		if tc == nil {
			continue
		}
		fn, _ := tc["function"].(map[string]any)
		if fn == nil {
			continue
		}
		name, _ := fn["name"].(string)
		desc, _ := fn["description"].(string)
		params := fn["parameters"]
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		result = append(result, map[string]any{
			"name": name, "description": desc, "input_schema": params,
		})
	}
	return result
}

// openAIToResponsesRequest 将 OpenAI Chat 请求转为 OpenAI Responses API 格式
func openAIToResponsesRequest(body []byte, upstream *UpstreamConfig) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		log.Printf("Warning: normalizeRawMessagesToolCallArguments failed: %v", err)
	}

	msgs, _ := req["messages"].([]any)
	var instructions string
	var input []map[string]any

	for _, m := range msgs {
		msg, _ := m.(map[string]any)
		if msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		content := msg["content"]

		if role == "system" {
			if s, ok := content.(string); ok {
				if instructions == "" {
					instructions = s
				} else {
					instructions += "\n" + s
				}
			}
			continue
		}

		if role == "assistant" {
			if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
				input = append(input, map[string]any{
					"type":    "reasoning",
					"summary": []any{map[string]any{"type": "summary_text", "text": rc}},
				})
			}
			text := extractTextFromContentParts(content)
			if text != "" {
				input = append(input, map[string]any{
					"role":    "assistant",
					"content": text,
				})
			}
			// Responses 协议要求 function_call 作为独立 item，不能挂在 assistant 消息上
			if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
				for _, tc := range tcs {
					tcMap, _ := tc.(map[string]any)
					id, _ := tcMap["id"].(string)
					fn, _ := tcMap["function"].(map[string]any)
					name, _ := fn["name"].(string)
					args, _ := fn["arguments"].(string)
					input = append(input, map[string]any{
						"type":      "function_call",
						"call_id":   id,
						"name":      name,
						"arguments": args,
					})
				}
			}
			continue
		}

		if role == "tool" {
			// Responses 协议使用 function_call_output 而不是 role=tool 消息
			toolCallID, _ := msg["tool_call_id"].(string)
			input = append(input, map[string]any{
				"type":    "function_call_output",
				"call_id": toolCallID,
				"output":  extractTextFromContentParts(content),
			})
			continue
		}

		// user / 其他角色
		input = append(input, map[string]any{
			"role":    role,
			"content": extractTextFromContentParts(content),
		})
	}

	respReq := map[string]any{
		"model": req["model"],
	}
	if instructions != "" {
		respReq["instructions"] = instructions
	}
	if len(input) > 0 {
		respReq["input"] = input
	}
	if stream, _ := req["stream"].(bool); stream {
		respReq["stream"] = true
	}
	if temp, _ := req["temperature"].(float64); temp != 0 {
		respReq["temperature"] = temp
	}
	if topP, _ := req["top_p"].(float64); topP != 0 {
		respReq["top_p"] = topP
	}
	if mt, _ := req["max_tokens"].(float64); mt > 0 {
		respReq["max_output_tokens"] = int(mt)
	}
	if tools, ok := req["tools"].([]any); ok && len(tools) > 0 {
		respReq["tools"] = convertChatToolsToResponses(tools)
	}
	if tc, ok := req["tool_choice"]; ok {
		respReq["tool_choice"] = convertChatToolChoiceToResponses(tc)
	}
	if ptc, ok := req["parallel_tool_calls"]; ok {
		respReq["parallel_tool_calls"] = ptc
	}
	if re, ok := req["reasoning_effort"].(string); ok && re != "" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(re), upstream)
	} else if effort := reasoningEffortFromThinking(req["thinking"]); effort != "" && effort != "none" {
		setResponsesReasoningEffort(respReq, mapConfiguredReasoningEffort(effort), upstream)
	}

	result, _ := json.Marshal(respReq)
	return result
}

// convertResponsesToChat 将 OpenAI Responses API 响应转为 OpenAI Chat 格式
func convertResponsesToChat(body []byte, modelID string) []byte {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}

	totalText := ""
	totalReasoning := ""
	var toolCalls []map[string]any
	if output, ok := resp["output"].([]any); ok {
		for _, item := range output {
			if m, ok := item.(map[string]any); ok {
				switch m["type"] {
				case "reasoning":
					reasoning := ""
					if summary, ok := m["summary"].([]any); ok {
						for _, s := range summary {
							if sm, ok := s.(map[string]any); ok {
								if t, ok := sm["text"].(string); ok {
									reasoning += t
								}
							}
						}
					}
					if reasoning == "" {
						if ec, ok := m["encrypted_content"].(string); ok && ec != "" {
							reasoning = ec
						}
					}
					if reasoning != "" {
						totalReasoning += reasoning
					}
				case "message":
					if content, ok := m["content"].([]any); ok {
						for _, block := range content {
							if b, ok := block.(map[string]any); ok {
								switch b["type"] {
								case "output_text":
									if t, ok := b["text"].(string); ok {
										totalText += t
									}
								}
							}
						}
					}
				case "function_call":
					callID, _ := m["call_id"].(string)
					name, _ := m["name"].(string)
					args, _ := m["arguments"].(string)
					toolCalls = append(toolCalls, map[string]any{
						"id":   callID,
						"type": "function",
						"function": map[string]any{
							"name":      name,
							"arguments": args,
						},
					})
				}
			}
		}
	}

	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	}
	if status, _ := resp["status"].(string); status == "incomplete" {
		finishReason = "length"
	}
	message := map[string]any{
		"role":    "assistant",
		"content": totalText,
	}
	if totalReasoning != "" {
		message["reasoning_content"] = totalReasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if resp["id"] == nil {
		resp["id"] = "resp_" + randomString(16)
	}
	if len(toolCalls) > 0 {
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
	}

	chatResp := map[string]any{
		"id":      resp["id"],
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := resp["usage"]; ok {
		chatResp["usage"] = usage
	}

	result, _ := json.Marshal(chatResp)
	return result
}

// ======================== 消息处理 ========================
// normalizeContent 是 dumb pipe 透传：保留 string 与 []any 两种入参形状
// （其它非常规类型走 json.Marshal 兜底），不解析或过滤任何 multimodal part。
// 能力协商由 opencode 客户端 + 上游负责；这里既不"硬降级"也不"补全"。
func normalizeContent(content any) any {
	if content == nil {
		return nil
	}
	if s, ok := content.(string); ok {
		return s
	}
	if arr, ok := content.([]any); ok {
		return arr
	}
	b, err := json.Marshal(content)
	if err != nil {
		return nil
	}
	return string(b)
}

func fixToolCallGaps(messages []Message) []Message {
	toolResponses := map[string]*Message{}
	for i := range messages {
		if messages[i].Role == "tool" && messages[i].ToolCallID != "" {
			toolResponses[messages[i].ToolCallID] = &messages[i]
		}
	}
	fixed := make([]Message, 0, len(messages)+len(messages)/4)
	emitted := map[string]bool{}
	for _, msg := range messages {
		if msg.Role == "tool" && msg.ToolCallID != "" {
			if emitted[msg.ToolCallID] {
				continue
			}
		}
		fixed = append(fixed, msg)
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				if resp, found := toolResponses[tc.ID]; found {
					fixed = append(fixed, *resp)
				} else {
					fixed = append(fixed, Message{Role: "tool", ToolCallID: tc.ID, Content: "Tool call result not available"})
				}
				emitted[tc.ID] = true
			}
		}
	}
	return fixed
}

func normalizeToolCallArguments(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "{}", nil
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "", err
	}
	obj, ok := parsed.(map[string]any)
	if !ok {
		return "", fmt.Errorf("must decode to JSON object, got %T", parsed)
	}
	normalized, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(normalized), nil
}

func toolCallArgumentsPreview(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	return truncatePreview(raw, 160)
}

func truncatePreview(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	runes := []rune(raw)
	if limit > 0 && len(runes) > limit {
		return string(runes[:limit]) + "..."
	}
	return raw
}

func messageContentPreview(content any) string {
	switch v := content.(type) {
	case nil:
		return ""
	case string:
		return truncatePreview(v, 160)
	case []any:
		return truncatePreview(extractTextFromContentParts(v), 160)
	default:
		b, _ := json.Marshal(v)
		return truncatePreview(string(b), 160)
	}
}

func logToolCallArgumentsValidationFailure(source string, messageIndex, toolCallIndex int, toolCallID, toolName, rawArgs string, content any, err error) {
	log.Printf("[tool-call arguments invalid] source=%s message_index=%d tool_call_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q content_preview=%q err=%v",
		source,
		messageIndex,
		toolCallIndex,
		toolCallID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		messageContentPreview(content),
		err,
	)
}

func logStreamToolCallArgumentsValidationFailure(source, itemID, callID, toolName, rawArgs string, outputIndex int, err error) {
	log.Printf("[tool-call stream invalid] source=%s item_id=%q output_index=%d tool_call_id=%q tool_name=%q arguments_len=%d arguments_preview=%q err=%v",
		source,
		itemID,
		outputIndex,
		callID,
		toolName,
		len(rawArgs),
		toolCallArgumentsPreview(rawArgs),
		err,
	)
}

func normalizeMessagesToolCallArguments(messages []Message) ([]Message, error) {
	for i := range messages {
		if messages[i].Role != "assistant" || len(messages[i].ToolCalls) == 0 {
			continue
		}
		for j := range messages[i].ToolCalls {
			normalized, err := normalizeToolCallArguments(messages[i].ToolCalls[j].Function.Arguments)
			if err != nil {
				logToolCallArgumentsValidationFailure(
					"normalizeMessagesToolCallArguments",
					i,
					j,
					messages[i].ToolCalls[j].ID,
					messages[i].ToolCalls[j].Function.Name,
					messages[i].ToolCalls[j].Function.Arguments,
					messages[i].Content,
					err,
				)
				return nil, fmt.Errorf("messages[%d].tool_calls[%d].function.arguments invalid JSON object string: %w; preview=%q", i, j, err, toolCallArgumentsPreview(messages[i].ToolCalls[j].Function.Arguments))
			}
			messages[i].ToolCalls[j].Function.Arguments = normalized
		}
	}
	return messages, nil
}

func normalizeRawMessagesToolCallArguments(rawMessages any) error {
	msgs, ok := rawMessages.([]any)
	if !ok {
		return nil
	}
	for i, rawMsg := range msgs {
		msg, ok := rawMsg.(map[string]any)
		if !ok || msg == nil {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "assistant" {
			continue
		}
		rawToolCalls, ok := msg["tool_calls"].([]any)
		if !ok {
			continue
		}
		for j, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok || tc == nil {
				continue
			}
			toolCallID, _ := tc["id"].(string)
			fn, ok := tc["function"].(map[string]any)
			if !ok || fn == nil {
				continue
			}
			toolName, _ := fn["name"].(string)
			var rawArgs string
			switch v := fn["arguments"].(type) {
			case string:
				rawArgs = v
			case nil:
				rawArgs = ""
			default:
				b, _ := json.Marshal(v)
				rawArgs = string(b)
			}
			normalized, err := normalizeToolCallArguments(rawArgs)
			if err != nil {
				logToolCallArgumentsValidationFailure(
					"normalizeRawMessagesToolCallArguments",
					i,
					j,
					toolCallID,
					toolName,
					rawArgs,
					msg["content"],
					err,
				)
				return fmt.Errorf("messages[%d].tool_calls[%d].function.arguments invalid JSON object string: %w; preview=%q", i, j, err, toolCallArgumentsPreview(rawArgs))
			}
			fn["arguments"] = normalized
		}
	}
	return nil
}

func ensureReasoningContent(messages []Message, withReasoning bool) []Message {
	// Only inject empty reasoning_content when WithReasoning is enabled (DeepSeek upstream).
	// Other upstreams don't need this and may reject the unknown field.
	if !withReasoning {
		return messages
	}
	for i := range messages {
		if messages[i].Role == "assistant" && messages[i].ReasoningContent == nil {
			empty := ""
			messages[i].ReasoningContent = &empty
		}
	}
	return messages
}

func convertMessagesForUpstream(messages []Message, withReasoning bool) []map[string]any {
	converted := make([]map[string]any, 0, len(messages))
	for _, msg := range messages {
		clean := map[string]any{}
		if msg.Role != "" {
			clean["role"] = msg.Role
		}
		content := normalizeContent(msg.Content)
		reasoningContent := msg.ReasoningContent
		// Strip x-anthropic-billing-header from system messages
		if msg.Role == "system" {
			if s, ok := content.(string); ok {
				content = strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
				if content == "" {
					continue
				}
			} else if s, ok := content.([]any); ok {
				// Handle multi-part content in system messages
				var cleaned []any
				for _, part := range s {
					p, ok := part.(map[string]any)
					if !ok {
						continue
					}
					if txt, ok := p["text"].(string); ok {
						txt = strings.TrimSpace(reBillingHeader.ReplaceAllString(txt, ""))
						if txt != "" {
							p["text"] = txt
							cleaned = append(cleaned, p)
						}
					}
				}
				if len(cleaned) == 0 {
					continue
				}
				content = cleaned
			}
		}
		shouldSendContent := content != nil
		if msg.Role == "assistant" && len(msg.ToolCalls) > 0 {
			switch v := content.(type) {
			case string:
				shouldSendContent = strings.TrimSpace(v) != ""
			case []any:
				shouldSendContent = len(v) > 0
			}
		}
		if shouldSendContent {
			clean["content"] = content
		}
		if withReasoning && reasoningContent != nil && *reasoningContent != "" {
			clean["reasoning_content"] = *reasoningContent
		}
		if len(msg.ToolCalls) > 0 {
			clean["tool_calls"] = msg.ToolCalls
		}
		if msg.ToolCallID != "" {
			clean["tool_call_id"] = msg.ToolCallID
		}
		if msg.Name != "" {
			clean["name"] = msg.Name
		}
		converted = append(converted, clean)
	}
	return converted
}

// ======================== 完整请求转换（含 thinking/reasoning_effort/ExtraBody） ========================

func convertRequest(req *OpenAIRequest, withReasoning bool) map[string]any {
	converted := map[string]any{
		"model":    req.Model,
		"messages": convertMessagesForUpstream(req.Messages, withReasoning),
		"stream":   req.Stream,
	}
	if req.Temperature != nil {
		converted["temperature"] = *req.Temperature
	}
	if req.MaxTokens != 0 {
		converted["max_tokens"] = req.MaxTokens
	}
	// Inject stream_options.include_usage for streaming requests.
	if req.Stream {
		streamOptions := map[string]any{"include_usage": true}
		if existing, ok := req.StreamOptions.(map[string]any); ok {
			for k, v := range existing {
				streamOptions[k] = v
			}
			streamOptions["include_usage"] = true
		}
		converted["stream_options"] = streamOptions
	}
	if req.TopP != nil {
		converted["top_p"] = *req.TopP
	}
	if len(req.Tools) > 0 {
		converted["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		converted["tool_choice"] = req.ToolChoice
	}

	// Only forward thinking/reasoning_effort when WithReasoning is enabled (DeepSeek upstream).
	// Other upstreams (Xunfei/ModelArts/OpenAI) don't need these fields and may reject them.
	if withReasoning {
		if req.Thinking != nil {
			converted["thinking"] = req.Thinking
		} else if req.ExtraBody != nil {
			if thinking, ok := req.ExtraBody["thinking"]; ok && thinking != nil {
				converted["thinking"] = thinking
			}
		}
	}
	if withReasoning && req.ReasoningEffort != "" {
		effortMap := getReasoningEffortMap()
		if mapped, ok := effortMap[req.ReasoningEffort]; ok {
			converted["reasoning_effort"] = mapped
		} else {
			converted["reasoning_effort"] = req.ReasoningEffort
		}
	}

	if req.ExtraBody != nil {
		for k, v := range req.ExtraBody {
			if _, exists := converted[k]; !exists {
				converted[k] = v
			}
		}
	}
	return converted
}
func buildUpstreamBody(req *OpenAIRequest, withReasoning ...bool) []byte {
	wr := len(withReasoning) > 0 && withReasoning[0]
	converted := convertRequest(req, wr)
	b, err := json.Marshal(converted)
	if err != nil {
		log.Printf("Error marshaling upstream body: %v", err)
	}
	return b
}

// ======================== Anthropic 格式兼容 ========================

func isAnthropicFormat(body []byte) bool {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		if typ, _ := obj["type"].(string); typ == "message" {
			return true
		}
	}
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start", "content_block_start", "content_block_delta",
			"content_block_stop", "message_delta", "message_stop", "ping":
			return true
		}
		return false
	}
	return false
}

func parseAnthropicSSE(body []byte) (map[string]any, string, string, []map[string]any) {
	lines := bytes.Split(body, []byte("\n"))
	var anthropicMsg map[string]any
	var textBuilder, thinkingBuilder, currentToolInputBuilder strings.Builder
	var currentToolUse map[string]any
	var toolUseBlocks []map[string]any
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal(line, &event); err != nil {
			continue
		}
		typ, _ := event["type"].(string)
		switch typ {
		case "message_start":
			if m, ok := event["message"].(map[string]any); ok {
				anthropicMsg = m
			}
		case "content_block_start":
			if cb, ok := event["content_block"].(map[string]any); ok {
				if cbType, _ := cb["type"].(string); cbType == "tool_use" {
					currentToolUse = cb
					currentToolInputBuilder.Reset()
				}
			}
		case "content_block_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if t, ok := delta["text"].(string); ok {
					textBuilder.WriteString(t)
				}
				if dt, _ := delta["type"].(string); dt == "thinking_delta" {
					if th, ok := delta["thinking"].(string); ok {
						thinkingBuilder.WriteString(th)
					}
				}
				if dt, _ := delta["type"].(string); dt == "input_json_delta" {
					if partial, ok := delta["partial_json"].(string); ok {
						currentToolInputBuilder.WriteString(partial)
					}
				}
			}
		case "content_block_stop":
			if currentToolUse != nil {
				inputStr := currentToolInputBuilder.String()
				var input any = inputStr
				var parsed any
				if json.Unmarshal([]byte(inputStr), &parsed) == nil {
					input = parsed
				}
				currentToolUse["input"] = input
				toolUseBlocks = append(toolUseBlocks, currentToolUse)
				currentToolUse = nil
			}
		case "message_delta":
			if delta, ok := event["delta"].(map[string]any); ok {
				if anthropicMsg == nil {
					anthropicMsg = map[string]any{}
				}
				if stop, ok := delta["stop_reason"].(string); ok {
					anthropicMsg["stop_reason"] = stop
				}
				if usage, ok := delta["usage"].(map[string]any); ok {
					anthropicMsg["usage"] = usage
				}
			}
		case "message_stop":
		case "error":
			return nil, "", "", nil
		}
	}
	return anthropicMsg, textBuilder.String(), thinkingBuilder.String(), toolUseBlocks
}

func buildOpenAIResponse(anthropicMsg map[string]any, text string, reasoning string, toolUseBlocks []map[string]any, modelID string) []byte {
	if anthropicMsg == nil {
		return nil
	}
	now := time.Now().Unix()
	role, _ := anthropicMsg["role"].(string)
	if role == "" {
		role = "assistant"
	}
	finishReason, _ := anthropicMsg["stop_reason"].(string)
	if finishReason == "tool_use" {
		finishReason = "tool_calls"
	} else if finishReason == "end_turn" {
		finishReason = "stop"
	} else if finishReason == "max_tokens" {
		finishReason = "length"
	}
	message := map[string]any{"role": role, "content": text}
	if reasoning != "" {
		message["reasoning_content"] = reasoning
	}
	choice := map[string]any{
		"index":         0,
		"message":       message,
		"finish_reason": finishReason,
	}
	if len(toolUseBlocks) > 0 {
		var toolCalls []map[string]any
		for _, tb := range toolUseBlocks {
			toolInput := tb["input"]
			argsJSON, _ := json.Marshal(toolInput)
			toolCalls = append(toolCalls, map[string]any{
				"id":   tb["id"],
				"type": "function",
				"function": map[string]any{
					"name":      tb["name"],
					"arguments": string(argsJSON),
				},
			})
		}
		choice["message"].(map[string]any)["tool_calls"] = toolCalls
		if text == "" {
			choice["message"].(map[string]any)["content"] = nil
		}
	}
	resp := map[string]any{
		"id":      anthropicMsg["id"],
		"object":  "chat.completion",
		"created": now,
		"model":   modelID,
		"choices": []map[string]any{choice},
	}
	if usage, ok := anthropicMsg["usage"].(map[string]any); ok {
		openAIUsage := map[string]any{}
		if v, ok := usage["input_tokens"]; ok {
			openAIUsage["prompt_tokens"] = v
		}
		if v, ok := usage["output_tokens"]; ok {
			openAIUsage["completion_tokens"] = v
		}
		if pt, ok1 := openAIUsage["prompt_tokens"]; ok1 {
			if ct, ok2 := openAIUsage["completion_tokens"]; ok2 {
				ptF, _ := pt.(float64)
				ctF, _ := ct.(float64)
				openAIUsage["total_tokens"] = int64(ptF + ctF)
			}
		}
		resp["usage"] = openAIUsage
	}
	result, _ := json.Marshal(resp)
	return result
}

func convertAnthropicMessageToOpenAI(msg map[string]any, modelID string) []byte {
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	var textBuilder strings.Builder
	var thinkingBuilder strings.Builder
	var toolUses []map[string]any
	if content, ok := msg["content"].([]any); ok {
		for _, c := range content {
			if block, ok := c.(map[string]any); ok {
				switch block["type"] {
				case "text":
					if t, ok := block["text"].(string); ok {
						textBuilder.WriteString(t)
					}
				case "thinking":
					if t, ok := block["thinking"].(string); ok {
						thinkingBuilder.WriteString(t)
					}
				case "tool_use":
					toolUses = append(toolUses, block)
				}
			}
		}
	}
	return buildOpenAIResponse(msg, textBuilder.String(), thinkingBuilder.String(), toolUses, modelID)
}

func convertAnthropicToOpenAI(body []byte, modelID string) []byte {
	var singleMsg map[string]any
	if json.Unmarshal(body, &singleMsg) == nil {
		if typ, _ := singleMsg["type"].(string); typ == "message" {
			return convertAnthropicMessageToOpenAI(singleMsg, modelID)
		}
	}
	msg, text, reasoning, toolUses := parseAnthropicSSE(body)
	if msg == nil {
		return body
	}
	if msg["model"] == nil {
		msg["model"] = modelID
	}
	return buildOpenAIResponse(msg, text, reasoning, toolUses, modelID)
}

// ======================== 响应清理 ========================

func cleanNulls(m map[string]any) {
	for k, v := range m {
		if v == nil {
			delete(m, k)
			continue
		}
		if s, ok := v.(string); ok && s == "" {
			delete(m, k)
		}
	}
}

func hasNonEmptyString(value any) bool {
	s, ok := value.(string)
	return ok && s != ""
}

func normalizeReasoningContent(m map[string]any) {
	if m == nil || hasNonEmptyString(m["reasoning_content"]) {
		return
	}
	if v, ok := m["reasoning"]; ok {
		m["reasoning_content"] = v
	}
}

func cleanStreamDelta(delta map[string]any) {
	normalizeReasoningContent(delta)
	if v, ok := delta["content"]; ok && v == nil {
		delete(delta, "content")
	}
	if s, ok := delta["content"].(string); ok && s == "" {
		delete(delta, "content")
	}
	if v, ok := delta["reasoning_content"]; ok && v == nil {
		delete(delta, "reasoning_content")
	}
	if s, ok := delta["reasoning_content"].(string); ok && s == "" {
		delete(delta, "reasoning_content")
	}
	// 删除与 reasoning_content 重复的 reasoning 字段
	if rc, ok := delta["reasoning_content"].(string); ok && rc != "" {
		delete(delta, "reasoning")
	}
	if v, ok := delta["reasoning"]; ok && v == nil {
		delete(delta, "reasoning")
	}
	if s, ok := delta["reasoning"].(string); ok && s == "" {
		delete(delta, "reasoning")
	}
	if s, ok := delta["role"].(string); ok && s == "" {
		delete(delta, "role")
	}
}

// convertStreamChunkWithUsage 转换流式 chunk 并同时提取 usage，避免二次解析
func convertStreamChunkWithUsage(line string) (string, map[string]any) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
		return line, nil
	}
	if !strings.HasPrefix(line, "data: ") {
		return line, nil
	}
	data := line[6:]
	var raw map[string]any
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return line, nil
	}

	// 提取 usage
	var usage map[string]any
	if u, ok := raw["usage"].(map[string]any); ok {
		usage = u
	}

	choices, ok := raw["choices"].([]any)
	if !ok || len(choices) == 0 {
		return "", usage
	}
	for i, c := range choices {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if delta, ok := choice["delta"].(map[string]any); ok {
			cleanStreamDelta(delta)
			choice["delta"] = delta
		}
		if msg, ok := choice["message"].(map[string]any); ok {
			normalizeReasoningContent(msg)
			cleanNulls(msg)
			choice["message"] = msg
		}
		if v, ok := choice["logprobs"]; ok && v == nil {
			delete(choice, "logprobs")
		}
		if v, ok := choice["finish_reason"]; ok && v == nil {
			delete(choice, "finish_reason")
		}
		if s, ok := choice["finish_reason"].(string); ok && s == "" {
			delete(choice, "finish_reason")
		}
		// 清理上游扩展字段
		delete(choice, "stop_reason")
		delete(choice, "token_ids")
		choices[i] = choice
	}
	raw["choices"] = choices
	if v, ok := raw["usage"]; ok && v == nil {
		delete(raw, "usage")
	}
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	converted, err := json.Marshal(raw)
	if err != nil {
		return line, usage
	}
	return "data: " + string(converted), usage
}

func convertResponse(data []byte) ([]byte, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		log.Printf("Warning: convertResponse unmarshal failed: %v", err)
		return data, nil
	}
	if choices, ok := raw["choices"].([]any); ok {
		for i, c := range choices {
			if choice, ok := c.(map[string]any); ok {
				if msg, ok := choice["message"].(map[string]any); ok {
					normalizeReasoningContent(msg)
					// 删除与 reasoning_content 重复的 reasoning 字段
					if rc, ok := msg["reasoning_content"].(string); ok && rc != "" {
						delete(msg, "reasoning")
					}
					cleanNulls(msg)
					choice["message"] = msg
				}
				if v, ok := choice["logprobs"]; ok && v == nil {
					delete(choice, "logprobs")
				}
				// 清理上游扩展字段
				delete(choice, "stop_reason")
				delete(choice, "token_ids")
				choices[i] = choice
			}
		}
		raw["choices"] = choices
	}
	if usage, ok := raw["usage"].(map[string]any); ok {
		cleanU := map[string]any{}
		if v, ok := usage["prompt_tokens"]; ok && v != nil {
			cleanU["prompt_tokens"] = v
		}
		if v, ok := usage["completion_tokens"]; ok && v != nil {
			cleanU["completion_tokens"] = v
		}
		if v, ok := usage["total_tokens"]; ok && v != nil {
			cleanU["total_tokens"] = v
		}
		if len(cleanU) > 0 {
			raw["usage"] = cleanU
		} else {
			delete(raw, "usage")
		}
	}
	// 清理上游顶层扩展字段
	delete(raw, "cost")
	delete(raw, "service_tier")
	delete(raw, "prompt_logprobs")
	delete(raw, "prompt_token_ids")
	delete(raw, "kv_transfer_params")
	return json.Marshal(raw)
}

func cloneBodyMap(bodyMap map[string]any) map[string]any {
	cp := make(map[string]any, len(bodyMap)+1)
	for k, v := range bodyMap {
		cp[k] = v
	}
	if thinking, ok := cp["thinking"].(map[string]any); ok {
		clone := make(map[string]any, len(thinking))
		for k, v := range thinking {
			clone[k] = v
		}
		cp["thinking"] = clone
	}
	if thinking, ok := cp["thinking"].(map[string]string); ok {
		clone := make(map[string]any, len(thinking))
		for k, v := range thinking {
			clone[k] = v
		}
		cp["thinking"] = clone
	}
	if messages, ok := cp["messages"].([]map[string]any); ok {
		clone := make([]map[string]any, 0, len(messages))
		for _, msg := range messages {
			msgClone := make(map[string]any, len(msg))
			for k, v := range msg {
				msgClone[k] = v
			}
			clone = append(clone, msgClone)
		}
		cp["messages"] = clone
	}
	if messages, ok := cp["messages"].([]any); ok {
		clone := make([]any, 0, len(messages))
		for _, item := range messages {
			if msg, ok := item.(map[string]any); ok {
				msgClone := make(map[string]any, len(msg))
				for k, v := range msg {
					msgClone[k] = v
				}
				clone = append(clone, msgClone)
			} else {
				clone = append(clone, item)
			}
		}
		cp["messages"] = clone
	}
	return cp
}

// ======================== 上游端点 ========================

func getUpstreamEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	switch upstream.APIType {
	case UpstreamOpenAI:
		return base + "/chat/completions"
	case UpstreamAnthropic:
		return base + "/messages"
	case UpstreamResponses:
		return base + "/responses"
	default:
		return base + "/chat/completions"
	}
}

func getUpstreamModelsEndpoint(upstream *UpstreamConfig) string {
	if upstream == nil || upstream.BaseURL == "" {
		return ""
	}
	base := strings.TrimRight(upstream.BaseURL, "/")
	return base + "/models"
}

// ttfbReadCloser wraps an io.ReadCloser and logs the time-to-first-byte
// on the first Read call, then delegates all subsequent calls to the inner ReadCloser.
type ttfbReadCloser struct {
	inner     io.ReadCloser
	once      sync.Once
	start     time.Time
	upstream  string
	model     string
	clientAPI string
	keySlot   string
	exitLabel string
}

func (r *ttfbReadCloser) Read(p []byte) (int, error) {
	n, err := r.inner.Read(p)
	r.once.Do(func() {
		ttfb := time.Since(r.start)
		log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s exit=%s ttfb=%s", r.clientAPI, r.upstream, r.model, r.keySlot, r.exitLabel, ttfb.Round(time.Millisecond))
	})
	return n, err
}

func (r *ttfbReadCloser) Close() error {
	return r.inner.Close()
}

func buildUpstreamRequest(endpoint, apiKey string, body []byte, upstream *UpstreamConfig) (*http.Request, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			req.Header.Set("x-api-key", apiKey)
			req.Header.Set("anthropic-version", "2023-06-01")
			req.Header.Set("anthropic-beta", "prompt-caching-2025-01-31")
		} else {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func prepareOpenAIUpstreamBody(reqBody []byte, modelID string, upstream *UpstreamConfig) ([]byte, error) {
	var bodyMap map[string]any
	if err := json.Unmarshal(reqBody, &bodyMap); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}
	bodyMap["model"] = modelID
	marshaled, _ := json.Marshal(bodyMap)
	tryBody := marshaled
	if upstream != nil {
		switch upstream.APIType {
		case UpstreamAnthropic:
			tryBody = openAIToAnthropicRequest(marshaled)
		case UpstreamResponses:
			tryBody = openAIToResponsesRequest(marshaled, upstream)
		}
	}
	return tryBody, nil
}

func callPreparedUpstream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, rawResponse ...bool) ([]byte, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream)
	retryDelay := 1 * time.Second
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s exit=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel())
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay, ""); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		c := getHTTPClient(false)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s exit=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel())
		startTTFB := time.Now()
		resp, err := c.Do(up)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay, ""); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			ttfb := time.Since(startTTFB)
			log.Printf("[ttfb] api=%s upstream=%s model=%s key=%s exit=%s ttfb=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel(), ttfb.Round(time.Millisecond))
			b, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				return nil, 0, nil, readErr
			}
			if len(rawResponse) > 0 && rawResponse[0] {
				// rawResponse: skip conversion, return as-is
			} else if upstream != nil && upstream.APIType == UpstreamResponses {
				b = convertResponsesToChat(b, modelID)
			} else if isAnthropicFormat(b) {
				b = convertAnthropicToOpenAI(b, modelID)
			}
			return b, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s exit=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel(), resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			if resp.StatusCode == http.StatusTooManyRequests {
				rotateSocks5OnRateLimit()
			}
			waitDelay := retryDelay
			if len(apiKeys) > 1 {
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex)
				if strings.TrimSpace(resp.Header.Get("Retry-After")) == "" && waitDelay > 300*time.Millisecond {
					waitDelay = 300 * time.Millisecond
				}
			}
			if err := waitForRetry(ctx, waitDelay, resp.Header.Get("Retry-After")); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return errBody, resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error: %s", string(errBody))
	}
}

func callUpstream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig, rawResponse ...bool) ([]byte, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream, rawResponse...)
}

func callPreparedUpstreamStream(ctx context.Context, preparedBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig) (io.ReadCloser, int, http.Header, error) {
	if upstream == nil || upstream.BaseURL == "" {
		return nil, 500, nil, fmt.Errorf("upstream not configured")
	}

	apiKey, apiKeyIndex, apiKeys := selectUpstreamAPIKey(upstreamName, upstream)
	retryDelay := 1 * time.Second
	for {
		select {
		case <-ctx.Done():
			log.Printf("[client disconnect] api=%s upstream=%s model=%s key=%s exit=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel())
			return nil, 0, nil, ctx.Err()
		default:
		}
		up, err := buildUpstreamRequest(getUpstreamEndpoint(upstream), apiKey, preparedBody, upstream)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay, ""); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config on build error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		c := getHTTPClient(true)
		log.Printf("[upstream request] api=%s upstream=%s model=%s key=%s exit=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel())
		startTTFB := time.Now()
		resp, err := c.Do(up)
		if err != nil {
			if err := waitForRetry(ctx, retryDelay, ""); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config on connection error too
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return nil, 500, nil, fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			wrappedBody := &ttfbReadCloser{
				inner:     resp.Body,
				start:     startTTFB,
				upstream:  effectiveUpstreamName(upstreamName),
				model:     modelID,
				clientAPI: clientAPI,
				keySlot:   formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)),
				exitLabel: currentSocks5ExitLabel(),
			}
			return wrappedBody, resp.StatusCode, resp.Header, nil
		}
		errBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if shouldRetryUpstreamStatus(resp.StatusCode) {
			log.Printf("[upstream retry] api=%s upstream=%s model=%s key=%s exit=%s status=%d retry_after=%q body=%s", clientAPI, effectiveUpstreamName(upstreamName), modelID, formatUpstreamAPIKeySlot(apiKeyIndex, len(apiKeys)), currentSocks5ExitLabel(), resp.StatusCode, resp.Header.Get("Retry-After"), string(errBody))
			if resp.StatusCode == http.StatusTooManyRequests {
				rotateSocks5OnRateLimit()
			}
			waitDelay := retryDelay
			if len(apiKeys) > 1 {
				apiKey, apiKeyIndex = rotateUpstreamAPIKey(apiKeys, apiKeyIndex)
				if strings.TrimSpace(resp.Header.Get("Retry-After")) == "" && waitDelay > 300*time.Millisecond {
					waitDelay = 300 * time.Millisecond
				}
			}
			if err := waitForRetry(ctx, waitDelay, resp.Header.Get("Retry-After")); err != nil {
				return nil, 0, nil, err
			}
			retryDelay = nextRetryDelay(retryDelay)
			// Refresh upstream config: user may have re-mapped or deleted this upstream
			newUpstreamName, newUpstream := resolveUpstream(upstreamName)
			if newUpstream == nil || newUpstream.BaseURL == "" {
				log.Printf("[upstream retry abort] api=%s upstream=%s no longer available, giving up", clientAPI, upstreamName)
				return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream %q no longer available", upstreamName)
			}
			upstreamName, upstream = newUpstreamName, newUpstream
			apiKey, apiKeyIndex, apiKeys = selectUpstreamAPIKey(upstreamName, upstream)
			retryDelay = 1 * time.Second
			continue
		}
		// Non-retryable error: return immediately
		errBody = mapUpstreamErrorBody(errBody, upstream.APIType)
		return io.NopCloser(bytes.NewReader(errBody)), resp.StatusCode, resp.Header.Clone(), fmt.Errorf("upstream error")
	}
}

func callUpstreamStream(ctx context.Context, reqBody []byte, upstreamName, modelID, clientAPI string, upstream *UpstreamConfig) (io.ReadCloser, int, http.Header, error) {
	tryBody, err := prepareOpenAIUpstreamBody(reqBody, modelID, upstream)
	if err != nil {
		return nil, 500, nil, err
	}
	return callPreparedUpstreamStream(ctx, tryBody, upstreamName, modelID, clientAPI, upstream)
}

func stripBillingHeaderText(s string) string {
	return strings.TrimSpace(reBillingHeader.ReplaceAllString(s, ""))
}

func stripBillingHeaderFromResponsesItems(items any) {
	arr, ok := items.([]any)
	if !ok {
		return
	}
	for _, item := range arr {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "system" && role != "developer" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = stripBillingHeaderText(content)
		case []any:
			for _, part := range content {
				pm, ok := part.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := pm["text"].(string); ok {
					pm["text"] = stripBillingHeaderText(text)
				}
			}
		}
	}
}

func ensureResponsesIncludeUsage(req map[string]any) {
	stream, _ := req["stream"].(bool)
	if !stream {
		return
	}
	if so, ok := req["stream_options"].(map[string]any); ok {
		so["include_usage"] = true
		req["stream_options"] = so
		return
	}
	req["stream_options"] = map[string]any{"include_usage": true}
}

func hasResponsesReasoning(req map[string]any) bool {
	if _, ok := req["reasoning"]; ok {
		return true
	}
	if _, ok := req["reasoning_effort"]; ok {
		return true
	}
	return false
}

func prepareAnthropicPassthroughBody(body []byte, modelID string) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	return json.Marshal(req)
}

func proxyAnthropicPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	var inputTokens, outputTokens, cacheCreationInputTokens, cacheReadInputTokens float64
	recordedUsage := false

	updateAnthropicUsage := func(usage map[string]any) {
		if usage == nil {
			return
		}
		if v, ok := getFloat(usage, "input_tokens"); ok && v > 0 {
			inputTokens = v
		}
		if v, ok := getFloat(usage, "cache_creation_input_tokens"); ok && v > 0 {
			cacheCreationInputTokens = v
		}
		if v, ok := getFloat(usage, "cache_read_input_tokens"); ok && v > 0 {
			cacheReadInputTokens = v
		}
		if v, ok := getFloat(usage, "output_tokens"); ok && v >= 0 {
			outputTokens = v
		}
	}

	recordAnthropicUsage := func() {
		if recordedUsage {
			return
		}
		promptTokens := inputTokens + cacheCreationInputTokens + cacheReadInputTokens
		totalTokens := promptTokens + outputTokens
		if totalTokens <= 0 {
			return
		}
		recordedUsage = true
		recordTokenUsage(model, int64(promptTokens), int64(outputTokens), int64(totalTokens))
	}
	defer func() {
		// If the stream ended after message_delta but before message_stop, still
		// keep the gateway stats consistent. Claude Code receives the raw stream;
		// this only affects this gateway's admin stats.
		if outputTokens > 0 {
			recordAnthropicUsage()
		}
	}()

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if data != "" && data != "[DONE]" {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						switch currentEvent {
						case "message_start":
							if msg, ok := payload["message"].(map[string]any); ok {
								if usage, ok := msg["usage"].(map[string]any); ok {
									updateAnthropicUsage(usage)
								}
							}
						case "message_delta":
							if usage, ok := payload["usage"].(map[string]any); ok {
								updateAnthropicUsage(usage)
							}
						case "message_stop":
							recordAnthropicUsage()
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func prepareResponsesPassthroughBody(body []byte, modelID string, alias ModelAlias) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}
	req["model"] = modelID
	if err := normalizeRawMessagesToolCallArguments(req["messages"]); err != nil {
		return nil, err
	}
	if instructions, ok := req["instructions"].(string); ok {
		req["instructions"] = stripBillingHeaderText(instructions)
	}
	stripBillingHeaderFromResponsesItems(req["input"])
	stripBillingHeaderFromResponsesItems(req["messages"])
	ensureResponsesIncludeUsage(req)

	return json.Marshal(req)
}

func proxyResponsesPassthroughStream(w http.ResponseWriter, body io.ReadCloser, model string) error {
	defer body.Close()
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(body)
	currentEvent := ""
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			if _, writeErr := io.WriteString(w, line); writeErr != nil {
				return writeErr
			}
			if strings.HasPrefix(line, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if data != "" && data != "[DONE]" && (currentEvent == "response.completed" || currentEvent == "response.incomplete") {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						if u := extractResponsesUsage(payload); u != nil {
							recordUsageMap(model, u)
						}
					}
				}
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

func extractResponsesUsage(payload map[string]any) map[string]any {
	if u, ok := payload["usage"].(map[string]any); ok {
		return u
	}
	if resp, ok := payload["response"].(map[string]any); ok {
		if u, ok := resp["usage"].(map[string]any); ok {
			return u
		}
	}
	return nil
}

func recordUsageMap(model string, u map[string]any) {
	pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
	ct, _ := getFloat(u, "completion_tokens", "output_tokens")
	tt, _ := getFloat(u, "total_tokens")
	if tt == 0 && pt+ct > 0 {
		tt = pt + ct
	}
	if tt > 0 {
		recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
	}
}

func responsesUsageToChatUsage(u map[string]any) map[string]any {
	if u == nil {
		return nil
	}
	pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
	ct, _ := getFloat(u, "completion_tokens", "output_tokens")
	tt, _ := getFloat(u, "total_tokens")
	if tt == 0 && pt+ct > 0 {
		tt = pt + ct
	}
	return map[string]any{
		"prompt_tokens":     int64(pt),
		"completion_tokens": int64(ct),
		"total_tokens":      int64(tt),
	}
}

func responsesStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string, recordUsage bool) {
	defer respBody.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)
	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	currentEvent := ""
	roleSent := false
	doneSent := false
	hasToolCalls := false
	toolIndexes := map[string]int{}
	nextToolIndex := 0

	emit := func(delta map[string]any, finishReason any, usage map[string]any) {
		if !roleSent {
			chunk := map[string]any{
				"id":      chunkID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]any{{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
			}
			b, _ := json.Marshal(chunk)
			w.Write([]byte("data: " + string(b) + "\n\n"))
			roleSent = true
		}
		if delta == nil {
			delta = map[string]any{}
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{{"index": 0, "delta": delta, "finish_reason": finishReason}},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		b, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(b) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	getToolIndex := func(item map[string]any) int {
		id, _ := item["id"].(string)
		if id == "" {
			id, _ = item["call_id"].(string)
		}
		if id == "" {
			id = fmt.Sprintf("tool_%d", nextToolIndex)
		}
		if idx, ok := toolIndexes[id]; ok {
			return idx
		}
		idx := nextToolIndex
		toolIndexes[id] = idx
		nextToolIndex++
		return idx
	}

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "event:") {
				currentEvent = strings.TrimSpace(strings.TrimPrefix(trimmed, "event:"))
			} else if strings.HasPrefix(trimmed, "data:") {
				data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
				if data == "[DONE]" {
					doneSent = true
					break
				}
				if data != "" {
					var payload map[string]any
					if json.Unmarshal([]byte(data), &payload) == nil {
						eventType, _ := payload["type"].(string)
						if eventType == "" {
							eventType = currentEvent
						}
						switch eventType {
						case "response.output_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"content": text}, nil, nil)
							}
						case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
							if text, _ := payload["delta"].(string); text != "" {
								emit(map[string]any{"reasoning_content": text}, nil, nil)
							}
						case "response.output_item.added":
							if item, ok := payload["item"].(map[string]any); ok {
								if typ, _ := item["type"].(string); typ == "function_call" {
									idx := getToolIndex(item)
									callID, _ := item["call_id"].(string)
									if callID == "" {
										callID, _ = item["id"].(string)
									}
									name, _ := item["name"].(string)
									hasToolCalls = true
									emit(map[string]any{"tool_calls": []map[string]any{{
										"index": float64(idx),
										"id":    callID,
										"type":  "function",
										"function": map[string]any{
											"name":      name,
											"arguments": "",
										},
									}}}, nil, nil)
								}
							}
						case "response.function_call_arguments.delta":
							itemID, _ := payload["item_id"].(string)
							if itemID == "" {
								itemID, _ = payload["call_id"].(string)
							}
							idx, ok := toolIndexes[itemID]
							if !ok {
								idx = nextToolIndex
								toolIndexes[itemID] = idx
								nextToolIndex++
							}
							if delta, _ := payload["delta"].(string); delta != "" {
								emit(map[string]any{"tool_calls": []map[string]any{{
									"index":    float64(idx),
									"function": map[string]any{"arguments": delta},
								}}}, nil, nil)
							}
						case "response.completed", "response.incomplete":
							usage := responsesUsageToChatUsage(extractResponsesUsage(payload))
							if recordUsage && usage != nil {
								recordUsageMap(model, usage)
							}
							finishReason := "stop"
							if hasToolCalls {
								finishReason = "tool_calls"
							}
							if eventType == "response.incomplete" {
								finishReason = "length"
							}
							emit(map[string]any{}, finishReason, usage)
						}
					}
				}
			}
		}
		if err != nil {
			break
		}
	}
	if !doneSent {
		w.Write([]byte("data: [DONE]\n\n"))
	}
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== 安全响应头过滤 ========================

var safeResponseHeaders = map[string]bool{
	"Content-Type":          true,
	"Retry-After":           true,
	"RateLimit-Limit":       true,
	"RateLimit-Remaining":   true,
	"RateLimit-Reset":       true,
	"X-RateLimit-Limit":     true,
	"X-RateLimit-Remaining": true,
	"X-RateLimit-Reset":     true,
}

func filterResponseHeaders(h http.Header) http.Header {
	filtered := make(http.Header)
	for k, v := range h {
		if safeResponseHeaders[k] {
			filtered[k] = v
		}
	}
	return filtered
}

func copyFilteredResponseHeaders(dst http.Header, src http.Header) {
	for k, values := range filterResponseHeaders(src) {
		dst.Del(k)
		for _, v := range values {
			dst.Add(k, v)
		}
	}
}

func normalizeUpstreamStatus(status int) int {
	if status < 100 || status > 999 {
		return http.StatusBadGateway
	}
	return status
}

func applyUpstreamErrorHeaders(w http.ResponseWriter, upstreamHeaders http.Header, status int) int {
	status = normalizeUpstreamStatus(status)
	copyFilteredResponseHeaders(w.Header(), upstreamHeaders)
	w.Header().Set("X-Upstream-Status", strconv.Itoa(status))
	if status == http.StatusTooManyRequests {
		w.Header().Set("X-Upstream-Rate-Limited", "true")
	}
	return status
}

// mapUpstreamErrorBody converts upstream error responses to standard OpenAI format
func mapUpstreamErrorBody(body []byte, upstreamType UpstreamType) []byte {
	if len(body) == 0 {
		return nil
	}
	trimmed := bytes.TrimSpace(body)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		for _, line := range bytes.Split(trimmed, []byte{'\n'}) {
			line = bytes.TrimSpace(line)
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
			if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			trimmed = payload
			break
		}
	}
	var parsed map[string]any
	if json.Unmarshal(trimmed, &parsed) != nil {
		return trimmed
	}
	// Already has OpenAI-format error
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if _, hasMsg := errObj["message"]; hasMsg {
			return trimmed
		}
	}
	// Anthropic: { "error": { "type": "...", "message": "..." } }
	if errObj, ok := parsed["error"].(map[string]any); ok {
		if msg, ok := errObj["message"].(string); ok {
			b, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"message": msg,
					"type":    errObj["type"],
				},
			})
			return b
		}
	}
	// Top-level message
	if msg, ok := parsed["message"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
				"type":    parsed["type"],
				"code":    parsed["type"],
			},
		})
		return b
	}
	// msg field
	if msg, ok := parsed["msg"].(string); ok {
		b, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"message": msg,
			},
		})
		return b
	}
	return trimmed
}

// ======================== Chat Completions Handler ========================

func chatCompletionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/chat/completions\n%s", cnt, string(body))
	}

	var req OpenAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(req.Model)
	req.Model = resolvedModel
	if req.Model == "" {
		modelIDs := getModelIDs()
		if len(modelIDs) > 0 {
			req.Model = modelIDs[0]
		} else {
			req.Model = "gpt-4o-mini"
		}
	}

	// 多模态路由：检测到图片时转发到配置的上游

	req.Messages = fixToolCallGaps(req.Messages)
	var toolArgsErr error
	req.Messages, toolArgsErr = normalizeMessagesToolCallArguments(req.Messages)
	if toolArgsErr != nil {
		log.Printf("[request invalid] path=/v1/chat/completions model=%q err=%v", req.Model, toolArgsErr)
		http.Error(w, toolArgsErr.Error(), http.StatusBadRequest)
		return
	}
	ensureReasoningEffort(&req, modelAliasInfo)
	req.Messages = ensureReasoningContent(req.Messages, modelAliasInfo.WithReasoning)
	upstreamBody := buildUpstreamBody(&req, modelAliasInfo.WithReasoning)

	if req.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
			return
		}
		defer upResp.Close()
		// 如果上游是 Anthropic，需要将 Anthropic SSE 流转为 OpenAI Chat SSE 格式
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			anthropicStreamToChatHandler(w, upResp, req.Model)
			return
		}
		if upstream != nil && upstream.APIType == UpstreamResponses {
			responsesStreamToChatHandler(w, upResp, req.Model, true)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		reader := bufio.NewReader(upResp)
		doneSeen := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					break
				}
				log.Printf("Error reading stream: %v", err)
				// 发送错误事件通知客户端
				w.Write([]byte("data: {\"error\":\"stream read error\"}\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				return
			}
			if doneSeen {
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed == "data: [DONE]" {
				doneSeen = true
				w.Write([]byte("data: [DONE]\n\n"))
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
				continue
			}

			out, usage := convertStreamChunkWithUsage(line)
			if out == "" {
				// 空choices chunk，但可能有 usage
				if usage != nil {
					pt, _ := usage["prompt_tokens"].(float64)
					ct, _ := usage["completion_tokens"].(float64)
					tt, _ := usage["total_tokens"].(float64)
					if tt > 0 {
						recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
					}
				}
				continue
			}

			// 提取 usage（已在 convertStreamChunkWithUsage 中解析）
			if usage != nil && !doneSeen {
				pt, _ := usage["prompt_tokens"].(float64)
				ct, _ := usage["completion_tokens"].(float64)
				tt, _ := usage["total_tokens"].(float64)
				if tt > 0 {
					recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
				}
			}

			w.Write([]byte(out))
			w.Write([]byte("\n\n"))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, req.Model, "chat", upstream)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error", "type": "upstream_error"}})
		}
		return
	}
	outBody := respBody
	convertedResp, err := convertResponse(respBody)
	if err == nil {
		outBody = convertedResp
	}
	// Record token usage
	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt == 0 && pt+ct > 0 {
				tt = pt + ct
			}
			if tt > 0 {
				recordTokenUsage(req.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(outBody)
}

// ======================== Models Handler ========================

func listModelsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	models := getAliasModelInfos()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"object": "list",
		"data":   models,
	})
}

// ======================== Anthropic Messages API ========================

func extractAnthropicSystemText(system any) string {
	if system == nil {
		return ""
	}
	switch v := system.(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, item := range v {
			if block, ok := item.(map[string]any); ok {
				if block["type"] == "text" {
					if text, ok := block["text"].(string); ok {
						parts = append(parts, text)
					}
				}
			}
		}
		return strings.Join(parts, "\n")
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func cleanJsonSchema(schema any) any {
	m, ok := schema.(map[string]any)
	if !ok {
		return schema
	}
	delete(m, "$schema")
	delete(m, "title")
	delete(m, "examples")
	delete(m, "additionalProperties")
	if m["type"] == "string" {
		delete(m, "format")
	}
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			m[k] = cleanJsonSchema(sub)
		}
		if arr, ok := v.([]any); ok {
			for i, elem := range arr {
				if sub, ok := elem.(map[string]any); ok {
					arr[i] = cleanJsonSchema(sub)
				}
			}
			m[k] = arr
		}
	}
	return m
}

func anthropicToOpenAIMessages(anthropicMsgs []AnthropicMessage, system any) []Message {
	var messages []Message
	if sysText := extractAnthropicSystemText(system); sysText != "" {
		messages = append(messages, Message{Role: "system", Content: sysText})
	}
	for _, msg := range anthropicMsgs {
		switch content := msg.Content.(type) {
		case string:
			messages = append(messages, Message{Role: msg.Role, Content: content})
		case []any:
			var textParts []string
			var reasoningParts []string
			var toolCalls []ToolCall
			var toolResults []Message
			var imageParts []map[string]any
			for _, item := range content {
				block, ok := item.(map[string]any)
				if !ok {
					continue
				}
				blockType, _ := block["type"].(string)
				switch blockType {
				case "text":
					if text, ok := block["text"].(string); ok && text != "" {
						textParts = append(textParts, text)
					}
				case "image":
					source, _ := block["source"].(map[string]any)
					if source != nil {
						srcType, _ := source["type"].(string)
						mediaType, _ := source["media_type"].(string)
						data, _ := source["data"].(string)
						if srcType == "base64" && data != "" {
							if mediaType == "" {
								mediaType = "image/png"
							}
							imageParts = append(imageParts, map[string]any{
								"type": "image_url",
								"image_url": map[string]string{
									"url": "data:" + mediaType + ";base64," + data,
								},
							})
						} else if srcType == "url" {
							if url, ok := source["url"].(string); ok && url != "" {
								imageParts = append(imageParts, map[string]any{
									"type": "image_url",
									"image_url": map[string]string{
										"url": url,
									},
								})
							}
						}
					}
				case "thinking":
					if thinking, ok := block["thinking"].(string); ok && thinking != "" {
						reasoningParts = append(reasoningParts, thinking)
					}
				case "tool_use":
					id, _ := block["id"].(string)
					name, _ := block["name"].(string)
					var args string
					switch input := block["input"].(type) {
					case string:
						args = input
					default:
						if input != nil {
							b, _ := json.Marshal(input)
							args = string(b)
						}
					}
					if args == "" {
						args = "{}"
					}
					toolCalls = append(toolCalls, ToolCall{
						ID:   id,
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: args,
						},
					})
				case "tool_result":
					toolUseID, _ := block["tool_use_id"].(string)
					var resultText string
					switch c := block["content"].(type) {
					case string:
						resultText = c
					case []any:
						var parts []string
						for _, p := range c {
							if pb, ok := p.(map[string]any); ok && pb["type"] == "text" {
								if t, ok := pb["text"].(string); ok {
									parts = append(parts, t)
								}
							}
						}
						resultText = strings.Join(parts, "\n")
					default:
						if c != nil {
							b, _ := json.Marshal(c)
							resultText = string(b)
						}
					}
					toolResults = append(toolResults, Message{
						Role:       "tool",
						ToolCallID: toolUseID,
						Content:    resultText,
					})
				}
			}
			om := Message{Role: msg.Role}
			if len(imageParts) > 0 {
				var contentArr []any
				for _, img := range imageParts {
					contentArr = append(contentArr, img)
				}
				if len(textParts) > 0 {
					contentArr = append(contentArr, map[string]any{
						"type": "text",
						"text": strings.Join(textParts, "\n"),
					})
				}
				om.Content = contentArr
			} else if len(textParts) > 0 {
				om.Content = strings.Join(textParts, "\n")
			} else if len(toolCalls) == 0 {
				om.Content = ""
			}
			if len(reasoningParts) > 0 {
				rc := strings.Join(reasoningParts, "\n")
				om.ReasoningContent = &rc
			}
			if len(toolCalls) > 0 {
				om.ToolCalls = toolCalls
			}
			messages = append(messages, om)
			messages = append(messages, toolResults...)
		default:
			b, _ := json.Marshal(content)
			messages = append(messages, Message{Role: msg.Role, Content: string(b)})
		}
	}
	return messages
}

func anthropicToOpenAITools(anthropicTools []AnthropicTool) []Tool {
	tools := make([]Tool, 0, len(anthropicTools))
	for _, ct := range anthropicTools {
		params := ct.InputSchema
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		params = cleanJsonSchema(params)
		paramsMap, ok := params.(map[string]any)
		if !ok {
			// 非对象类型（如数组、字符串）的 input_schema 退化为空对象
			paramsMap = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		tools = append(tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        ct.Name,
				Description: ct.Description,
				Parameters:  paramsMap,
			},
		})
	}
	return tools
}

func convertAnthropicToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		// Anthropic 也允许字符串，但标准是对象；直接透传
		return v
	case map[string]any:
		t, _ := v["type"].(string)
		switch t {
		case "auto", "none":
			return t
		case "any":
			// Anthropic any -> OpenAI required
			return "required"
		case "tool":
			name, _ := v["name"].(string)
			if name == "" {
				return "auto"
			}
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		default:
			return choice
		}
	default:
		return choice
	}
}

func buildAnthropicErrorBody(errorType, message string) []byte {
	if strings.TrimSpace(errorType) == "" {
		errorType = "api_error"
	}
	if strings.TrimSpace(message) == "" {
		message = "upstream error"
	}
	b, _ := json.Marshal(map[string]any{
		"type": "error",
		"error": map[string]any{
			"type":    errorType,
			"message": message,
		},
	})
	return b
}

func upstreamErrorToAnthropic(errObj any, fallback string) (string, string) {
	errType := "api_error"
	msg := fallback
	if m, ok := errObj.(map[string]any); ok {
		if s, ok := m["type"].(string); ok && strings.TrimSpace(s) != "" {
			errType = s
		}
		if s, ok := m["message"].(string); ok && strings.TrimSpace(s) != "" {
			msg = s
		}
		if code, ok := m["code"]; ok && code != nil {
			msg = fmt.Sprintf("%s (upstream code: %v)", msg, code)
		}
	} else if s, ok := errObj.(string); ok && strings.TrimSpace(s) != "" {
		msg = s
	}
	if strings.TrimSpace(msg) == "" {
		msg = "upstream error"
	}
	return errType, msg
}

func openAIToAnthropicResponse(chatBody []byte, model string) ([]byte, bool) {
	var raw map[string]any
	if err := json.Unmarshal(chatBody, &raw); err == nil {
		if errObj, ok := raw["error"]; ok {
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream returned error")
			log.Printf("Warning: upstream returned error object: type=%s message=%s", errType, msg)
			return buildAnthropicErrorBody(errType, msg), false
		}
	}

	var chat struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Created int64  `json:"created"`
		Choices []struct {
			Message struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: openAIToAnthropicResponse unmarshal failed: %v", err)
		return buildAnthropicErrorBody("api_error", "upstream returned invalid JSON: "+err.Error()), false
	}
	if len(chat.Choices) == 0 {
		preview := truncatePreview(string(chatBody), 500)
		log.Printf("Warning: upstream returned chat completion without choices: %s", preview)
		return buildAnthropicErrorBody("api_error", "upstream returned chat completion without choices"), false
	}

	content := []AnthropicContent{}
	stopReason := "end_turn"

	msg := chat.Choices[0].Message
	fr := chat.Choices[0].FinishReason
	reasoning := msg.ReasoningContent
	if reasoning == "" {
		reasoning = msg.Reasoning
	}
	if reasoning != "" {
		content = append(content, AnthropicContent{
			Type:     "thinking",
			Thinking: reasoning,
		})
	}
	if msg.Content != "" {
		content = append(content, AnthropicContent{
			Type: "text",
			Text: msg.Content,
		})
	}
	for _, tc := range msg.ToolCalls {
		var input any
		json.Unmarshal([]byte(tc.Function.Arguments), &input)
		if input == nil {
			input = map[string]any{}
		}
		content = append(content, AnthropicContent{
			Type:  "tool_use",
			ID:    tc.ID,
			Name:  tc.Function.Name,
			Input: input,
		})
	}
	switch fr {
	case "stop":
		stopReason = "end_turn"
	case "length":
		stopReason = "max_tokens"
	case "tool_calls", "function_call":
		stopReason = "tool_use"
	}

	if len(content) == 0 {
		log.Printf("Warning: upstream returned empty assistant message for model %s", model)
		return buildAnthropicErrorBody("api_error", "upstream returned empty assistant message"), false
	}

	resp := AnthropicResponse{
		ID:           fmt.Sprintf("msg_%s", randomString(24)),
		Type:         "message",
		Role:         "assistant",
		Content:      content,
		Model:        model,
		StopReason:   stopReason,
		StopSequence: nil,
	}
	if chat.Usage != nil {
		inputTokens, _ := getFloat(chat.Usage, "input_tokens", "prompt_tokens")
		outputTokens, _ := getFloat(chat.Usage, "output_tokens", "completion_tokens")
		resp.Usage = &AnthropicUsage{
			InputTokens:  int(toFloat64(inputTokens)),
			OutputTokens: int(toFloat64(outputTokens)),
		}
	}
	result, _ := json.Marshal(resp)
	return result, true
}

func toFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	default:
		return 0
	}
}

func getFloat(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch n := v.(type) {
			case float64:
				return n, true
			case float32:
				return float64(n), true
			case int:
				return float64(n), true
			case int64:
				return float64(n), true
			case int32:
				return float64(n), true
			}
		}
	}
	return 0, false
}

func anthropicMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/messages\n%s", cnt, string(body))
	}

	var anthropicReq AnthropicRequest
	if err := json.Unmarshal(body, &anthropicReq); err != nil {
		http.Error(w, `{"type":"error","error":{"type":"invalid_request_error","message":"Invalid JSON"}}`, http.StatusBadRequest)
		return
	}
	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(anthropicReq.Model)
	anthropicReq.Model = resolvedModel

	// 上游是 Anthropic 类型时，下游入口与上游同为 Anthropic 协议，直接透传
	if upstream != nil && upstream.APIType == UpstreamAnthropic {
		rawBody, err := prepareAnthropicPassthroughBody(body, anthropicReq.Model)
		if err != nil {
			log.Printf("[request invalid] path=/v1/messages mode=passthrough model=%q err=%v", anthropicReq.Model, err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": err.Error()}})
			return
		}
		if anthropicReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream)
			if err != nil || status < 200 || status >= 300 {
				errResp := map[string]any{
					"type":  "error",
					"error": map[string]string{"type": "api_error", "message": "upstream error"},
				}
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(errResp)
				return
			}
			defer upResp.Close()
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyAnthropicPassthroughStream(w, upResp, anthropicReq.Model); err != nil && debugMode {
				log.Printf("[anthropic raw stream passthrough error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, anthropicReq.Model, "messages", upstream, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
			}
			return
		}
		// Record token usage
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				it, _ := u["input_tokens"].(float64)
				ot, _ := u["output_tokens"].(float64)
				tt := it + ot
				if tt > 0 {
					recordTokenUsage(anthropicReq.Model, int64(it), int64(ot), int64(tt))
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[client response] (Anthropic passthrough)\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 上游非 Anthropic 类型，走 Chat 中间格式转换

	messages := anthropicToOpenAIMessages(anthropicReq.Messages, anthropicReq.System)
	messages = fixToolCallGaps(messages)
	var toolArgsErr error
	messages, toolArgsErr = normalizeMessagesToolCallArguments(messages)
	if toolArgsErr != nil {
		log.Printf("[request invalid] path=/v1/messages model=%q err=%v", anthropicReq.Model, toolArgsErr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "invalid_request_error", "message": toolArgsErr.Error()}})
		return
	}

	chatReq := OpenAIRequest{
		Model:    anthropicReq.Model,
		Messages: messages,
		Stream:   anthropicReq.Stream,
		Thinking: anthropicReq.Thinking,
	}
	if anthropicReq.MaxTokens > 0 {
		chatReq.MaxTokens = anthropicReq.MaxTokens
	}
	if anthropicReq.Temperature != nil {
		chatReq.Temperature = anthropicReq.Temperature
	}
	if anthropicReq.TopP != nil {
		chatReq.TopP = anthropicReq.TopP
	}
	if len(anthropicReq.Tools) > 0 {
		chatReq.Tools = anthropicToOpenAITools(anthropicReq.Tools)
	}
	if anthropicReq.ToolChoice != nil {
		chatReq.ToolChoice = convertAnthropicToolChoice(anthropicReq.ToolChoice)
	} else if len(chatReq.Tools) > 0 {
		chatReq.ToolChoice = "auto"
	}

	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo.WithReasoning)

	if anthropicReq.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream)
		if err != nil || status < 200 || status >= 300 {
			errResp := map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": "upstream error"},
			}
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(errResp)
			return
		}
		defer upResp.Close()
		// 注：Anthropic 上游已在上方同协议直通处理，此处不会到达。
		// Responses 上游：先转为 Chat SSE 流，再转为 Anthropic SSE 流
		if upstream != nil && upstream.APIType == UpstreamResponses {
			pr2, pw2 := io.Pipe()
			go func() {
				defer pw2.Close()
				chatW2 := &pipeResponseWriter{w: pw2}
				// The outer anthropicStreamHandler records the converted usage.
				// Avoid double-counting gateway stats for Responses -> Anthropic.
				responsesStreamToChatHandler(chatW2, upResp, anthropicReq.Model, false)
			}()
			anthropicStreamHandler(w, io.NopCloser(pr2), anthropicReq.Model)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Anthropic SSE 流
			anthropicStreamHandler(w, upResp, anthropicReq.Model)
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "messages", upstream)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "upstream error"}})
		}
		return
	}

	anthropicRespBody, convertedOK := openAIToAnthropicResponse(respBody, anthropicReq.Model)
	if !convertedOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		w.Write(anthropicRespBody)
		return
	}

	// Record token usage
	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt > 0 {
				recordTokenUsage(anthropicReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[client response]\n%s", string(anthropicRespBody))
	}
	w.Write(anthropicRespBody)
}

func anthropicStreamHandler(w http.ResponseWriter, respBody io.ReadCloser, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	msgID := fmt.Sprintf("msg_%s", randomString(24))
	blockIndex := 0
	thinkingBlockOpen := false
	textBlockOpen := false
	toolCallAccumulator := map[int]map[string]string{}
	toolCallOrder := []int{}
	messageStartSent := false
	finishSeen := false
	finalStopReason := "end_turn"
	fullUsage := map[string]any{}
	defer func() {
		if len(fullUsage) > 0 {
			pt, _ := fullUsage["prompt_tokens"].(float64)
			ct, _ := fullUsage["completion_tokens"].(float64)
			tt, _ := fullUsage["total_tokens"].(float64)
			if tt > 0 {
				recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
			}
		}
	}()

	emitAnthropicEvent := func(event string, data any) {
		jsonData, err := json.Marshal(data)
		if err != nil {
			log.Printf("Error marshaling Anthropic SSE event: %v", err)
			return
		}
		w.Write([]byte("event: " + event + "\n"))
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	closeThinkingBlock := func() {
		if !thinkingBlockOpen {
			return
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         blockIndex - 1,
			"content_block": map[string]any{"type": "thinking"},
		})
		thinkingBlockOpen = false
	}

	closeTextBlock := func() {
		if !textBlockOpen {
			return
		}
		emitAnthropicEvent("content_block_stop", map[string]any{
			"type":          "content_block_stop",
			"index":         blockIndex - 1,
			"content_block": map[string]any{"type": "text"},
		})
		textBlockOpen = false
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			break
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if errObj, ok := chunk["error"]; ok {
			errType, msg := upstreamErrorToAnthropic(errObj, "upstream stream returned error")
			emitAnthropicEvent("error", map[string]any{
				"type": "error",
				"error": map[string]any{
					"type":    errType,
					"message": msg,
				},
			})
			return
		}

		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				fullUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		if !messageStartSent {
			messageStartSent = true
			emitAnthropicEvent("message_start", map[string]any{
				"type": "message_start",
				"message": map[string]any{
					"id":            msgID,
					"type":          "message",
					"role":          "assistant",
					"content":       []any{},
					"model":         model,
					"stop_reason":   nil,
					"stop_sequence": nil,
					"usage":         map[string]any{"input_tokens": 0, "output_tokens": 0},
				},
			})
			emitAnthropicEvent("ping", map[string]any{"type": "ping"})
		}

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				closeTextBlock()
				if !thinkingBlockOpen {
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":     "thinking",
							"thinking": "",
						},
					})
					thinkingBlockOpen = true
					blockIndex++
				}
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": blockIndex - 1,
					"delta": map[string]any{
						"type":     "thinking_delta",
						"thinking": rcStr,
					},
				})
			}
		}

		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ := c.(string)
			if contentStr != "" {
				closeThinkingBlock()
				if !textBlockOpen {
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type": "text",
							"text": "",
						},
					})
					textBlockOpen = true
					blockIndex++
				}
				emitAnthropicEvent("content_block_delta", map[string]any{
					"type":  "content_block_delta",
					"index": blockIndex - 1,
					"delta": map[string]any{
						"type": "text_delta",
						"text": contentStr,
					},
				})
			}
		}

		if rawToolCalls, ok := delta["tool_calls"].([]any); ok {
			for _, rawTC := range rawToolCalls {
				tc, ok := rawTC.(map[string]any)
				if !ok {
					continue
				}
				idxFloat, _ := tc["index"].(float64)
				upstreamIndex := int(idxFloat)

				closeThinkingBlock()
				closeTextBlock()

				if _, exists := toolCallAccumulator[upstreamIndex]; !exists {
					callID, _ := tc["id"].(string)
					if callID == "" {
						callID = "toolu_" + randomString(12)
					}
					fn, _ := tc["function"].(map[string]any)
					name, _ := fn["name"].(string)
					toolCallAccumulator[upstreamIndex] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					toolCallOrder = append(toolCallOrder, upstreamIndex)
					emitAnthropicEvent("content_block_start", map[string]any{
						"type":  "content_block_start",
						"index": blockIndex,
						"content_block": map[string]any{
							"type":  "tool_use",
							"id":    callID,
							"name":  name,
							"input": map[string]any{},
						},
					})
					blockIndex++
				}

				fn, _ := tc["function"].(map[string]any)
				if argDelta, ok := fn["arguments"].(string); ok && argDelta != "" {
					toolCallAccumulator[upstreamIndex]["args"] += argDelta
					emitAnthropicEvent("content_block_delta", map[string]any{
						"type":  "content_block_delta",
						"index": blockIndex - 1,
						"delta": map[string]any{
							"type":         "input_json_delta",
							"partial_json": argDelta,
						},
					})
				}
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			fullUsage = usage
		}

		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			closeThinkingBlock()
			closeTextBlock()

			for _, idx := range toolCallOrder {
				acc := toolCallAccumulator[idx]
				emitAnthropicEvent("content_block_stop", map[string]any{
					"type":  "content_block_stop",
					"index": blockIndex - len(toolCallOrder) + indexOfInt(toolCallOrder, idx),
					"content_block": map[string]any{
						"type":  "tool_use",
						"id":    acc["id"],
						"name":  acc["name"],
						"input": map[string]any{},
					},
				})
			}

			switch finishReason {
			case "length":
				finalStopReason = "max_tokens"
			case "tool_calls", "function_call":
				finalStopReason = "tool_use"
			default:
				finalStopReason = "end_turn"
			}
			finishSeen = true
			// continue reading remaining chunks (usage chunk arrives after finish_reason)
		}
	}
	closeThinkingBlock()
	closeTextBlock()
	if !messageStartSent {
		emitAnthropicEvent("error", map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "api_error",
				"message": "upstream stream ended without message_start",
			},
		})
		return
	}

	inputTokens := 0
	if v, ok := fullUsage["prompt_tokens"]; ok {
		inputTokens = int(toFloat64(v))
	}
	outputTokens := 0
	if v, ok := fullUsage["completion_tokens"]; ok {
		outputTokens = int(toFloat64(v))
	}

	if !finishSeen {
		finalStopReason = "end_turn"
	}

	emitAnthropicEvent("message_delta", map[string]any{
		"type": "message_delta",
		"delta": map[string]any{
			"stop_reason":   finalStopReason,
			"stop_sequence": nil,
		},
		"usage": map[string]any{
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		},
	})
	emitAnthropicEvent("message_stop", map[string]any{"type": "message_stop"})
}

func indexOfInt(slice []int, val int) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return 0
}

// ======================== Anthropic 流式转换 ========================

// pipeResponseWriter 适配 io.Writer 到 http.ResponseWriter 接口
type pipeResponseWriter struct {
	w      io.Writer
	header http.Header
}

func (p *pipeResponseWriter) Header() http.Header {
	if p.header == nil {
		p.header = make(http.Header)
	}
	return p.header
}

func (p *pipeResponseWriter) Write(data []byte) (int, error) {
	return p.w.Write(data)
}

func (p *pipeResponseWriter) WriteHeader(code int) {}

func (p *pipeResponseWriter) Flush() {
	// no-op for pipe; writes are synchronous
}

// anthropicStreamToChatHandler 将上游 Anthropic SSE 流实时转为 OpenAI Chat SSE 格式并写入客户端
func anthropicStreamToChatHandler(w http.ResponseWriter, respBody io.ReadCloser, model string) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(respBody)

	chunkID := "chatcmpl-" + randomString(16)
	created := time.Now().Unix()
	roleSent := false
	toolCallAccumulator := map[int]map[string]string{}
	toolCallOrder := []int{}
	fullUsage := map[string]any{}

	defer func() {
		if len(fullUsage) > 0 {
			pt, _ := fullUsage["input_tokens"].(float64)
			ct, _ := fullUsage["output_tokens"].(float64)
			if pt > 0 || ct > 0 {
				recordTokenUsage(model, int64(pt), int64(ct), int64(pt+ct))
			}
		}
	}()

	emitChatChunk := func(delta map[string]any, finishReason any, usage map[string]any) {
		// 清理空 content，避免客户端收到 content:"" 的 chunk
		if c, ok := delta["content"].(string); ok && c == "" {
			delete(delta, "content")
		}
		if finishReason == nil || finishReason == "" {
			finishReason = nil
		}
		chunk := map[string]any{
			"id":      chunkID,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   model,
			"choices": []map[string]any{
				{
					"index":         0,
					"delta":         delta,
					"finish_reason": finishReason,
				},
			},
		}
		if usage != nil {
			chunk["usage"] = usage
		}
		jsonData, _ := json.Marshal(chunk)
		w.Write([]byte("data: " + string(jsonData) + "\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading Anthropic stream: %v", err)
			break
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}

		// Parse Anthropic SSE data lines
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var event map[string]any
		if json.Unmarshal([]byte(line[6:]), &event) != nil {
			continue
		}

		eventType, _ := event["type"].(string)

		switch eventType {
		case "message_start":
			if msg, ok := event["message"].(map[string]any); ok {
				if id, ok := msg["id"].(string); ok && id != "" {
					chunkID = "chatcmpl-" + id
				}
				if u, ok := msg["usage"].(map[string]any); ok {
					fullUsage = u
				}
			}
			if !roleSent {
				emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
				roleSent = true
			}

		case "content_block_start":
			block, _ := event["content_block"].(map[string]any)
			if block != nil {
				blockType, _ := block["type"].(string)
				switch blockType {
				case "tool_use":
					idx := len(toolCallAccumulator)
					callID, _ := block["id"].(string)
					name, _ := block["name"].(string)
					toolCallAccumulator[idx] = map[string]string{
						"id":   callID,
						"name": name,
						"args": "",
					}
					toolCallOrder = append(toolCallOrder, idx)
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index": float64(idx),
								"id":    callID,
								"type":  "function",
								"function": map[string]any{
									"name":      name,
									"arguments": "",
								},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "content_block_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj == nil {
				continue
			}
			deltaType, _ := deltaObj["type"].(string)
			switch deltaType {
			case "thinking_delta":
				thinking, _ := deltaObj["thinking"].(string)
				if thinking != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"reasoning_content": thinking}, nil, nil)
				}
			case "text_delta":
				text, _ := deltaObj["text"].(string)
				if text != "" {
					if !roleSent {
						emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
						roleSent = true
					}
					emitChatChunk(map[string]any{"content": text}, nil, nil)
				}
			case "input_json_delta":
				partialJSON, _ := deltaObj["partial_json"].(string)
				index, _ := event["index"].(float64)
				idx := int(index)
				if tc, ok := toolCallAccumulator[idx]; ok {
					tc["args"] += partialJSON
					delta := map[string]any{
						"tool_calls": []map[string]any{
							{
								"index":    float64(idx),
								"function": map[string]any{"arguments": partialJSON},
							},
						},
					}
					emitChatChunk(delta, nil, nil)
				}
			}

		case "message_delta":
			deltaObj, _ := event["delta"].(map[string]any)
			if deltaObj != nil {
				stopReason, _ := deltaObj["stop_reason"].(string)
				finishReason := ""
				switch stopReason {
				case "end_turn":
					finishReason = "stop"
				case "max_tokens":
					finishReason = "length"
				case "tool_use":
					finishReason = "tool_calls"
				default:
					if stopReason != "" {
						finishReason = stopReason
					}
				}
				usage, _ := event["usage"].(map[string]any)
				if usage != nil {
					if ot, ok := usage["output_tokens"].(float64); ok {
						fullUsage["output_tokens"] = ot
					}
				}
				chatUsage := map[string]any{}
				if pt, ok := fullUsage["input_tokens"].(float64); ok {
					chatUsage["prompt_tokens"] = int64(pt)
				}
				if ot, ok := fullUsage["output_tokens"].(float64); ok {
					chatUsage["completion_tokens"] = int64(ot)
				}
				if _, ok := chatUsage["prompt_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if it, ok3 := u["input_tokens"].(float64); ok3 {
							chatUsage["prompt_tokens"] = int64(it)
							fullUsage["input_tokens"] = it
						}
					}
				}
				if _, ok := chatUsage["completion_tokens"]; !ok {
					if u, ok2 := event["usage"].(map[string]any); ok2 {
						if ot, ok3 := u["output_tokens"].(float64); ok3 {
							chatUsage["completion_tokens"] = int64(ot)
							fullUsage["output_tokens"] = ot
						}
					}
				}
				pt := float64(0)
				if v, ok := chatUsage["prompt_tokens"].(int64); ok {
					pt = float64(v)
				}
				ct := float64(0)
				if v, ok := chatUsage["completion_tokens"].(int64); ok {
					ct = float64(v)
				}
				chatUsage["total_tokens"] = int64(pt + ct)
				if !roleSent {
					emitChatChunk(map[string]any{"role": "assistant", "content": ""}, nil, nil)
					roleSent = true
				}
				emitChatChunk(map[string]any{}, finishReason, chatUsage)
			}

		case "message_stop":
			// nothing extra
		case "ping":
			// ignore
		}
	}

	w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Responses API ========================

func responsesInputToMessages(input any, instructions string) []Message {
	var messages []Message
	if instructions != "" {
		messages = append(messages, Message{Role: "system", Content: instructions})
	}
	switch v := input.(type) {
	case string:
		messages = append(messages, Message{Role: "user", Content: v})
	case []any:
		var pendingAssistant *Message
		ensurePendingAssistant := func() *Message {
			if pendingAssistant == nil {
				pendingAssistant = &Message{Role: "assistant", Content: ""}
			}
			return pendingAssistant
		}
		flushPendingAssistant := func() {
			if pendingAssistant == nil {
				return
			}
			if pendingAssistant.Content == nil {
				pendingAssistant.Content = ""
			}
			messages = append(messages, *pendingAssistant)
			pendingAssistant = nil
		}
		appendPendingReasoning := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if msg.ReasoningContent == nil || *msg.ReasoningContent == "" {
				rc := text
				msg.ReasoningContent = &rc
				return
			}
			rc := *msg.ReasoningContent + "\n" + text
			msg.ReasoningContent = &rc
		}
		appendPendingText := func(text string) {
			if text == "" {
				return
			}
			msg := ensurePendingAssistant()
			if existing, ok := msg.Content.(string); ok && existing != "" {
				msg.Content = existing + "\n" + text
			} else {
				msg.Content = text
			}
		}
		for _, item := range v {
			switch elem := item.(type) {
			case string:
				flushPendingAssistant()
				messages = append(messages, Message{Role: "user", Content: elem})
			case map[string]any:
				itemType, _ := elem["type"].(string)
				switch itemType {
				case "function_call", "tool_call":
					if pendingAssistant != nil {
						if existing, ok := pendingAssistant.Content.(string); ok && strings.TrimSpace(existing) != "" && len(pendingAssistant.ToolCalls) == 0 {
							flushPendingAssistant()
						}
					}
					if tc, ok := responsesToolCallFromItem(elem); ok {
						msg := ensurePendingAssistant()
						msg.ToolCalls = append(msg.ToolCalls, tc)
					}
				case "function_call_output", "tool_result":
					flushPendingAssistant()
					callID, output := responsesToolOutputFromItem(elem)
					if callID != "" {
						messages = append(messages, Message{Role: "tool", ToolCallID: callID, Content: output})
					}
					continue
				case "reasoning":
					text := extractTextFromContentParts(elem["summary"])
					if text == "" {
						text = extractTextFromContentParts(elem["content"])
					}
					if text == "" {
						text, _ = elem["text"].(string)
					}
					appendPendingReasoning(text)
					continue
				case "message", "":
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					if role == "developer" {
						role = "system"
					}
					if role == "assistant" {
						text := extractTextFromContentParts(elem["content"])
						if pendingAssistant != nil && len(pendingAssistant.ToolCalls) > 0 && text != "" {
							flushPendingAssistant()
						}
						appendPendingText(text)
					} else {
						flushPendingAssistant()
						content := responsesContentToChatContent(elem["content"])
						if role == "system" {
							content = extractTextFromContentParts(elem["content"])
						}
						messages = append(messages, Message{Role: role, Content: content})
					}
				default:
					flushPendingAssistant()
					role := "user"
					if r, ok := elem["role"].(string); ok && r != "" {
						role = r
					}
					content := responsesContentToChatContent(elem["content"])
					if content == "" || content == nil {
						b, _ := json.Marshal(elem)
						content = string(b)
					}
					messages = append(messages, Message{Role: role, Content: content})
				}
			default:
				flushPendingAssistant()
				b, _ := json.Marshal(elem)
				messages = append(messages, Message{Role: "user", Content: string(b)})
			}
		}
		flushPendingAssistant()
	default:
		b, _ := json.Marshal(v)
		messages = append(messages, Message{Role: "user", Content: string(b)})
	}
	return messages
}

func responsesToolCallFromItem(elem map[string]any) (ToolCall, bool) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["id"].(string)
	}
	name, _ := elem["name"].(string)
	args, _ := elem["arguments"].(string)
	if args == "" {
		if rawArgs, ok := elem["arguments"]; ok && rawArgs != nil {
			b, _ := json.Marshal(rawArgs)
			args = string(b)
		}
	}
	if name == "" {
		if tu, ok := elem["tool_use"].(map[string]any); ok {
			name, _ = tu["name"].(string)
			if callID == "" {
				callID, _ = tu["id"].(string)
			}
			if a, ok := tu["arguments"].(string); ok {
				args = a
			} else if inp, ok := tu["input"]; ok {
				b, _ := json.Marshal(inp)
				args = string(b)
			}
		}
	}
	if callID == "" || name == "" {
		return ToolCall{}, false
	}
	if args == "" {
		args = "{}"
	}
	return ToolCall{
		ID:   callID,
		Type: "function",
		Function: FunctionCall{
			Name:      name,
			Arguments: args,
		},
	}, true
}

func responsesToolOutputFromItem(elem map[string]any) (string, any) {
	callID, _ := elem["call_id"].(string)
	if callID == "" {
		callID, _ = elem["tool_use_id"].(string)
	}
	if callID == "" {
		return "", ""
	}
	var output any
	switch o := elem["output"].(type) {
	case string:
		output = o
	case []any:
		if converted := responsesContentToChatContent(o); converted != "" && converted != nil {
			output = converted
		} else {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	default:
		if o != nil {
			b, _ := json.Marshal(o)
			output = string(b)
		}
	}
	switch v := output.(type) {
	case nil:
		output = "[tool output missing]"
	case string:
		if v == "" {
			output = "[tool output missing]"
		}
	case []any:
		if len(v) == 0 {
			output = "[tool output missing]"
		}
	}
	return callID, output
}

// convertChatToolsToResponses 将 OpenAI Chat tools 转为 Responses tools 格式
func convertChatToolsToResponses(tools []any) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok || tool == nil {
			continue
		}
		t, _ := tool["type"].(string)
		if t == "" {
			t = "function"
		}
		// Chat: {type:function, function:{name,description,parameters}}
		// Responses: {type:function, name, description, parameters}
		if fn, ok := tool["function"].(map[string]any); ok && fn != nil {
			item := map[string]any{"type": "function"}
			if name, ok := fn["name"].(string); ok {
				item["name"] = name
			}
			if desc, ok := fn["description"].(string); ok {
				item["description"] = desc
			}
			if params, ok := fn["parameters"]; ok {
				item["parameters"] = params
			} else {
				item["parameters"] = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			out = append(out, item)
			continue
		}
		// 已是 Responses 形态则尽量保留
		item := map[string]any{"type": t}
		for _, k := range []string{"name", "description", "parameters", "function"} {
			if v, ok := tool[k]; ok {
				item[k] = v
			}
		}
		out = append(out, item)
	}
	return out
}

// convertChatToolChoiceToResponses 将 OpenAI Chat tool_choice 转为 Responses tool_choice
func convertChatToolChoiceToResponses(choice any) any {
	if choice == nil {
		return nil
	}
	switch v := choice.(type) {
	case string:
		return v
	case map[string]any:
		// Chat: {"type":"function","function":{"name":"xxx"}}
		// Responses: {"type":"function","name":"xxx"}
		if t, _ := v["type"].(string); t == "function" {
			if fn, ok := v["function"].(map[string]any); ok {
				if name, ok := fn["name"].(string); ok && name != "" {
					return map[string]any{"type": "function", "name": name}
				}
			}
			if name, ok := v["name"].(string); ok && name != "" {
				return map[string]any{"type": "function", "name": name}
			}
		}
		return v
	default:
		return choice
	}
}

func convertResponsesTools(tools []ResponsesTool) []Tool {
	converted, _ := convertResponsesToolsWithMappings(tools)
	return converted
}

func convertResponsesToolsWithMappings(tools []ResponsesTool) ([]Tool, map[string]ResponseToolNameMapping) {
	converted := make([]Tool, 0, len(tools))
	mappings := map[string]ResponseToolNameMapping{}
	for _, tool := range tools {
		switch tool.Type {
		case "function":
			if fn, ok := responsesToolFunction(tool, ""); ok {
				converted = append(converted, Tool{Type: "function", Function: fn})
			}
		case "namespace":
			namespace := strings.TrimSpace(tool.Name)
			for _, nested := range tool.Tools {
				if nested.Type != "function" {
					continue
				}
				if fn, ok := responsesToolFunction(nested, namespace); ok {
					converted = append(converted, Tool{Type: "function", Function: fn})
					mappings[fn.Name] = ResponseToolNameMapping{
						Namespace: namespace,
						Name:      responseToolName(nested),
					}
				}
			}
		}
	}
	return converted, mappings
}

func responsesToolFunction(tool ResponsesTool, namespace string) (ToolFunction, bool) {
	fn := ToolFunction{
		Name:        tool.Name,
		Description: tool.Description,
		Parameters:  tool.Parameters,
	}
	if tool.Function != nil {
		fn = *tool.Function
	}
	fn.Name = strings.TrimSpace(fn.Name)
	if fn.Name == "" {
		return ToolFunction{}, false
	}
	if namespace != "" {
		fn.Name = flattenNamespaceToolName(namespace, fn.Name)
	}
	if fn.Parameters == nil {
		fn.Parameters = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	return fn, true
}

func responseToolName(tool ResponsesTool) string {
	if tool.Function != nil {
		return strings.TrimSpace(tool.Function.Name)
	}
	return strings.TrimSpace(tool.Name)
}

func flattenNamespaceToolName(namespace, toolName string) string {
	ns := strings.TrimSuffix(strings.TrimSpace(namespace), "__")
	name := strings.TrimSpace(toolName)
	if ns == "" {
		return name
	}
	return ns + "__" + name
}

func convertResponsesToolChoice(choice any) any {
	if choice == nil {
		return nil
	}
	choiceMap, ok := choice.(map[string]any)
	if !ok {
		return choice
	}
	if choiceMap["type"] == "function" {
		if name, ok := choiceMap["name"].(string); ok && name != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": name},
			}
		}
	}
	if choiceMap["type"] == "namespace" {
		namespace, _ := choiceMap["name"].(string)
		toolName, _ := choiceMap["tool"].(string)
		if toolName == "" {
			toolName, _ = choiceMap["tool_name"].(string)
		}
		if namespace != "" && toolName != "" {
			return map[string]any{
				"type":     "function",
				"function": map[string]any{"name": flattenNamespaceToolName(namespace, toolName)},
			}
		}
	}
	return choice
}

func collectFunctionOutputs(items []any) map[string]string {
	outputs := map[string]string{}
	for _, item := range items {
		elem, ok := item.(map[string]any)
		if !ok || elem["type"] != "function_call_output" {
			continue
		}
		callID, _ := elem["call_id"].(string)
		if callID == "" {
			continue
		}
		switch v := elem["output"].(type) {
		case string:
			outputs[callID] = v
		default:
			b, _ := json.Marshal(v)
			outputs[callID] = string(b)
		}
	}
	return outputs
}

func responseFunctionCallItem(itemID, status, arguments, callID, name string, mappings map[string]ResponseToolNameMapping) map[string]any {
	item := map[string]any{
		"id":        itemID,
		"type":      "function_call",
		"status":    status,
		"arguments": arguments,
		"call_id":   callID,
		"name":      name,
	}
	if mapping, ok := responseToolNameMapping(name, mappings); ok {
		item["name"] = mapping.Name
		item["namespace"] = mapping.Namespace
	}
	return item
}

func responseToolNameMapping(name string, mappings map[string]ResponseToolNameMapping) (ResponseToolNameMapping, bool) {
	if len(mappings) == 0 {
		return ResponseToolNameMapping{}, false
	}
	if mapping, ok := mappings[name]; ok {
		return mapping, true
	}
	normalized := normalizeResponseToolCallKey(name)
	if mapping, ok := mappings[normalized]; ok {
		return mapping, true
	}
	return ResponseToolNameMapping{}, false
}

func normalizeResponseToolCallKey(name string) string {
	normalized := strings.NewReplacer(":", "__", ".", "__", "/", "__", "-", "_").Replace(strings.TrimSpace(name))
	for strings.Contains(normalized, "___") {
		normalized = strings.ReplaceAll(normalized, "___", "__")
	}
	return normalized
}

func responsesContentToChatContent(content any) any {
	if content == nil {
		return ""
	}
	if s, ok := content.(string); ok {
		return s
	}
	parts, ok := content.([]any)
	if !ok {
		text := extractTextFromContentParts(content)
		if text != "" {
			return text
		}
		return ""
	}

	var converted []any
	var textParts []string
	hasImage := false
	for _, p := range parts {
		part, ok := p.(map[string]any)
		if !ok {
			continue
		}
		partType, _ := part["type"].(string)
		switch partType {
		case "input_text", "output_text", "summary_text", "text":
			if text, ok := part["text"].(string); ok && text != "" {
				textParts = append(textParts, text)
				converted = append(converted, map[string]any{"type": "text", "text": text})
			}
		case "input_image", "image_url":
			imageURL := responsesImageURLFromPart(part)
			if imageURL != nil {
				hasImage = true
				converted = append(converted, map[string]any{"type": "image_url", "image_url": imageURL})
			}
		}
	}
	if len(converted) == 0 {
		return ""
	}
	if hasImage {
		return converted
	}
	return strings.Join(textParts, "\n")
}

func responsesImageURLFromPart(part map[string]any) map[string]any {
	url := ""
	detail := ""
	if v, ok := part["image_url"].(string); ok {
		url = v
	}
	if imageURL, ok := part["image_url"].(map[string]any); ok {
		if u, ok := imageURL["url"].(string); ok {
			url = u
		}
		if d, ok := imageURL["detail"].(string); ok {
			detail = d
		}
	}
	if url == "" {
		if v, ok := part["url"].(string); ok {
			url = v
		}
	}
	if detail == "" {
		detail, _ = part["detail"].(string)
	}
	if url == "" {
		return nil
	}
	imageURL := map[string]any{"url": url}
	if detail != "" {
		imageURL["detail"] = detail
	}
	return imageURL
}

func extractTextFromContentParts(content any) string {
	parts, ok := content.([]any)
	if !ok {
		if s, ok := content.(string); ok {
			return s
		}
		return ""
	}
	var texts []string
	for _, p := range parts {
		if part, ok := p.(map[string]any); ok {
			if part["type"] == "input_text" || part["type"] == "output_text" || part["type"] == "summary_text" || part["type"] == "text" {
				if t, ok := part["text"].(string); ok {
					texts = append(texts, t)
				}
			}
		}
	}
	return strings.Join(texts, "\n")
}

func responsesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	cnt := requestCount.Add(1)
	if debugMode {
		log.Printf("[request #%d] POST /v1/responses\n%s", cnt, string(body))
	}

	var respReq ResponsesAPIRequest
	if err := json.Unmarshal(body, &respReq); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	resolvedModel, modelAliasInfo, upstreamName, upstream := resolveModel(respReq.Model)
	respReq.Model = resolvedModel
	if respReq.Model == "" {
		modelIDs := getModelIDs()
		if len(modelIDs) > 0 {
			respReq.Model = modelIDs[0]
		} else {
			respReq.Model = "deepseek-v4-flash-free"
		}
	}

	if upstream != nil && upstream.APIType == UpstreamResponses {
		rawBody, err := prepareResponsesPassthroughBody(body, respReq.Model, modelAliasInfo)
		if err != nil {
			log.Printf("[request invalid] path=/v1/responses mode=passthrough model=%q err=%v", respReq.Model, err)
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if respReq.Stream {
			upResp, status, upHeader, err := callPreparedUpstreamStream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream)
			if err != nil || status < 200 || status >= 300 {
				w.Header().Set("Content-Type", "application/json")
				status = applyUpstreamErrorHeaders(w, upHeader, status)
				w.WriteHeader(status)
				if upResp != nil {
					errBody, _ := io.ReadAll(upResp)
					if len(errBody) > 0 {
						w.Write(errBody)
						return
					}
				}
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.WriteHeader(http.StatusOK)
			if err := proxyResponsesPassthroughStream(w, upResp, respReq.Model); err != nil && debugMode {
				log.Printf("[responses raw stream proxy error] %v", err)
			}
			return
		}

		respBody, status, upHeader, err := callPreparedUpstream(r.Context(), rawBody, upstreamName, respReq.Model, "responses", upstream, true)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if len(respBody) > 0 {
				w.Write(respBody)
			} else {
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			}
			return
		}
		var usageResp map[string]any
		if json.Unmarshal(respBody, &usageResp) == nil {
			if u, ok := usageResp["usage"].(map[string]any); ok {
				pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
				ct, _ := getFloat(u, "completion_tokens", "output_tokens")
				tt, _ := getFloat(u, "total_tokens")
				if tt == 0 && pt+ct > 0 {
					tt = pt + ct
				}
				if tt > 0 {
					recordTokenUsage(respReq.Model, int64(pt), int64(ct), int64(tt))
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if debugMode {
			log.Printf("[responses raw response]\n%s", string(respBody))
		}
		w.Write(respBody)
		return
	}

	// 多模态路由

	messages := respReq.Messages
	if len(messages) == 0 {
		messages = responsesInputToMessages(respReq.Input, respReq.Instructions)
	} else if respReq.Instructions != "" {
		messages = append([]Message{{Role: "system", Content: respReq.Instructions}}, messages...)
	}

	chatReq := OpenAIRequest{
		Model:    respReq.Model,
		Messages: messages,
		Stream:   respReq.Stream,
	}
	toolNameMappings := map[string]ResponseToolNameMapping{}
	if respReq.Temperature != 0 {
		chatReq.Temperature = &respReq.Temperature
	}
	if respReq.MaxTokens != 0 {
		chatReq.MaxTokens = respReq.MaxTokens
	}
	if respReq.TopP != 0 {
		chatReq.TopP = &respReq.TopP
	}
	if len(respReq.Tools) > 0 {
		chatReq.Tools, toolNameMappings = convertResponsesToolsWithMappings(respReq.Tools)
	}
	if respReq.ToolChoice != nil {
		chatReq.ToolChoice = convertResponsesToolChoice(respReq.ToolChoice)
	}
	if respReq.ParallelToolCalls != nil {
		chatReq.ExtraBody = map[string]any{"parallel_tool_calls": *respReq.ParallelToolCalls}
	}
	// Only forward Responses API reasoning.effort when WithReasoning is enabled (DeepSeek upstream).
	// Other upstreams (Xunfei/ModelArts/OpenAI) don't need this field and may reject it.
	if modelAliasInfo.WithReasoning && respReq.Reasoning.Effort != "" {
		if respReq.Reasoning.Effort != "none" {
			chatReq.ReasoningEffort = respReq.Reasoning.Effort
		}
	}

	chatReq.Messages = fixToolCallGaps(chatReq.Messages)
	chatReq.Messages, err = normalizeMessagesToolCallArguments(chatReq.Messages)
	if err != nil {
		log.Printf("[request invalid] path=/v1/responses model=%q err=%v", chatReq.Model, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ensureReasoningEffort(&chatReq, modelAliasInfo)
	chatReq.Messages = ensureReasoningContent(chatReq.Messages, modelAliasInfo.WithReasoning)

	upstreamBody := buildUpstreamBody(&chatReq, modelAliasInfo.WithReasoning)

	// callUpstream/callUpstreamStream 内部会根据当前请求选中的 upstream.APIType 自动转换请求格式
	// 不需要在这里手动转换，避免双重转换导致请求体丢失
	// 流式响应需要特殊处理
	if respReq.Stream {
		upResp, status, upHeader, err := callUpstreamStream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream)
		if err != nil || status < 200 || status >= 300 {
			w.Header().Set("Content-Type", "application/json")
			status = applyUpstreamErrorHeaders(w, upHeader, status)
			w.WriteHeader(status)
			if upResp != nil {
				errBody, _ := io.ReadAll(upResp)
				if len(errBody) > 0 {
					w.Write(errBody)
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
			return
		}
		defer upResp.Close()

		// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
		resp := &http.Response{
			StatusCode: status,
			Body:       upResp,
			Header:     make(http.Header),
		}
		if upstream != nil && upstream.APIType == UpstreamAnthropic {
			// Anthropic 上游：先转为 Chat SSE 流，再转为 Responses SSE 流
			pr, pw := io.Pipe()
			go func() {
				defer pw.Close()
				chatW := &pipeResponseWriter{w: pw}
				anthropicStreamToChatHandler(chatW, upResp, chatReq.Model)
			}()
			chatResp := &http.Response{
				StatusCode: status,
				Body:       pr,
				Header:     make(http.Header),
			}
			responsesStreamHandler(w, r, chatResp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
		} else {
			// OpenAI 上游：Chat SSE 流直接转为 Responses SSE 流
			responsesStreamHandler(w, r, resp, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)
		}
		return
	}

	respBody, status, upHeader, err := callUpstream(r.Context(), upstreamBody, upstreamName, chatReq.Model, "responses", upstream)
	if err != nil || status < 200 || status >= 300 {
		w.Header().Set("Content-Type", "application/json")
		status = applyUpstreamErrorHeaders(w, upHeader, status)
		w.WriteHeader(status)
		if len(respBody) > 0 {
			w.Write(respBody)
		} else {
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "upstream error"}})
		}
		return
	}

	// 注：Responses 上游已在上方同协议直通处理，此处不会到达。
	// callUpstream 返回的 respBody 已统一为 Chat 格式，再转为 Responses API 格式
	responsesBody := convertChatToResponses(respBody, chatReq.Model, chatReq.Tools, chatReq.ToolChoice, toolNameMappings)

	var usageResp2 map[string]any
	if json.Unmarshal(respBody, &usageResp2) == nil {
		if u, ok := usageResp2["usage"].(map[string]any); ok {
			pt, _ := getFloat(u, "prompt_tokens", "input_tokens")
			ct, _ := getFloat(u, "completion_tokens", "output_tokens")
			tt, _ := getFloat(u, "total_tokens")
			if tt == 0 && pt+ct > 0 {
				tt = pt + ct
			}
			if tt > 0 {
				recordTokenUsage(chatReq.Model, int64(pt), int64(ct), int64(tt))
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if debugMode {
		log.Printf("[responses response]\n%s", string(responsesBody))
	}
	w.Write(responsesBody)
}

// ======================== Responses Stream Handler ========================

func responsesStreamHandler(w http.ResponseWriter, _ *http.Request, resp *http.Response, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReader(resp.Body)

	responseID := "resp_" + time.Now().Format("20060102150405") + "_" + randomString(8)
	reasoningID := "rs_" + responseID
	msgID := "msg_" + responseID + "_0"
	createdAt := time.Now().Unix()
	seq := 0

	reasoningStarted := false
	reasoningDone := false
	messageStarted := false
	messageDone := false
	isIncomplete := false
	incompleteReason := ""
	terminalFinishSeen := false
	fullReasoning := ""
	fullText := ""
	totalUsage := map[string]any{}
	createdSent := false
	toolCalls := map[int]map[string]any{}
	toolOrder := []int{}

	messageOutputIndex := func() int {
		if reasoningStarted {
			return 1
		}
		return 0
	}

	reasoningItem := func(status string) map[string]any {
		item := map[string]any{
			"id":      reasoningID,
			"type":    "reasoning",
			"summary": []any{},
		}
		if status != "" {
			item["status"] = status
		}
		if status == "completed" {
			item["encrypted_content"] = ""
		}
		if fullReasoning != "" {
			item["summary"] = []any{map[string]any{"type": "summary_text", "text": fullReasoning}}
		}
		return item
	}

	messageItem := func(status string) map[string]any {
		content := []any{map[string]any{
			"type":        "output_text",
			"annotations": []any{},
			"logprobs":    []any{},
			"text":        fullText,
		}}
		return map[string]any{
			"id":      msgID,
			"type":    "message",
			"status":  status,
			"content": content,
			"role":    "assistant",
		}
	}

	emitReasoningDone := func() {
		if !reasoningStarted || reasoningDone {
			return
		}
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_text.done", map[string]any{
			"type":            "response.reasoning_summary_text.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"text":            fullReasoning,
		})
		seq++
		emitSSEEvent(w, flusher, "response.reasoning_summary_part.done", map[string]any{
			"type":            "response.reasoning_summary_part.done",
			"sequence_number": seq,
			"item_id":         reasoningID,
			"output_index":    0,
			"summary_index":   0,
			"part":            map[string]any{"type": "summary_text", "text": fullReasoning},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    0,
			"item":            reasoningItem("completed"),
		})
		reasoningDone = true
	}

	emitMessageDone := func() {
		if !messageStarted || messageDone {
			return
		}
		idx := messageOutputIndex()
		seq++
		emitSSEEvent(w, flusher, "response.output_text.done", map[string]any{
			"type":            "response.output_text.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"text":            fullText,
			"logprobs":        []any{},
		})
		seq++
		emitSSEEvent(w, flusher, "response.content_part.done", map[string]any{
			"type":            "response.content_part.done",
			"sequence_number": seq,
			"item_id":         msgID,
			"output_index":    idx,
			"content_index":   0,
			"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": fullText},
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            messageItem("completed"),
		})
		messageDone = true
	}

	emitToolCallDone := func(idx int, call map[string]any) {
		if done, _ := call["done"].(bool); done {
			return
		}
		itemID, _ := call["item_id"].(string)
		callID, _ := call["call_id"].(string)
		name, _ := call["name"].(string)
		args, _ := call["arguments"].(string)
		normalizedArgs, err := normalizeToolCallArguments(args)
		if err != nil {
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.emitToolCallDone", itemID, callID, name, args, idx, err)
			isIncomplete = true
			if incompleteReason == "" {
				incompleteReason = "tool_call_arguments_incomplete"
			}
			return
		}
		call["arguments"] = normalizedArgs
		call["done"] = true
		seq++
		emitSSEEvent(w, flusher, "response.function_call_arguments.done", map[string]any{
			"type":            "response.function_call_arguments.done",
			"sequence_number": seq,
			"item_id":         itemID,
			"output_index":    idx,
			"arguments":       normalizedArgs,
		})
		seq++
		emitSSEEvent(w, flusher, "response.output_item.done", map[string]any{
			"type":            "response.output_item.done",
			"sequence_number": seq,
			"output_index":    idx,
			"item":            responseFunctionCallItem(itemID, "completed", normalizedArgs, callID, name, toolNameMappings),
		})
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("Error reading stream: %v", err)
			return
		}
		if debugMode && strings.HasPrefix(line, "data: ") {
			log.Printf("[upstream raw chunk] %s", strings.TrimSpace(line[6:]))
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "data: [DONE]" || trimmed == "[DONE]" {
			break
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		var chunk map[string]any
		if err := json.Unmarshal([]byte(line[6:]), &chunk); err != nil {
			continue
		}
		if !createdSent {
			if id, ok := chunk["id"].(string); ok && id != "" {
				responseID = id
				reasoningID = "rs_" + responseID + "_0"
				msgID = "msg_" + responseID + "_0"
			}
			if created, ok := chunk["created"].(float64); ok {
				createdAt = int64(created)
			}
			seq++
			emitSSEEvent(w, flusher, "response.created", map[string]any{
				"type":            "response.created",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress", "background": false, "error": nil, "output": []any{}},
			})
			seq++
			emitSSEEvent(w, flusher, "response.in_progress", map[string]any{
				"type":            "response.in_progress",
				"sequence_number": seq,
				"response":        map[string]any{"id": responseID, "object": "response", "created_at": createdAt, "status": "in_progress"},
			})
			createdSent = true
		}
		choices, ok := chunk["choices"].([]any)
		if !ok || len(choices) == 0 {
			if usage, ok := chunk["usage"].(map[string]any); ok {
				totalUsage = usage
			}
			continue
		}

		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		normalizeReasoningContent(delta)
		finishReason, _ := choice["finish_reason"].(string)

		if rc, ok := delta["reasoning_content"]; ok {
			rcStr, _ := rc.(string)
			if rcStr != "" {
				if !reasoningStarted {
					seq++
					emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
						"type":            "response.output_item.added",
						"sequence_number": seq,
						"output_index":    0,
						"item":            reasoningItem("in_progress"),
					})
					seq++
					emitSSEEvent(w, flusher, "response.reasoning_summary_part.added", map[string]any{
						"type":            "response.reasoning_summary_part.added",
						"sequence_number": seq,
						"item_id":         reasoningID,
						"output_index":    0,
						"summary_index":   0,
						"part":            map[string]any{"type": "summary_text", "text": ""},
					})
					reasoningStarted = true
				}
				fullReasoning += rcStr
				seq++
				emitSSEEvent(w, flusher, "response.reasoning_summary_text.delta", map[string]any{
					"type":            "response.reasoning_summary_text.delta",
					"sequence_number": seq,
					"item_id":         reasoningID,
					"output_index":    0,
					"summary_index":   0,
					"delta":           rcStr,
				})
			}
		}

		contentStr := ""
		if c, ok := delta["content"]; ok && c != nil {
			contentStr, _ = c.(string)
		}
		if contentStr != "" {
			emitReasoningDone()
			if !messageStarted {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			fullText += contentStr
			seq++
			emitSSEEvent(w, flusher, "response.output_text.delta", map[string]any{
				"type":            "response.output_text.delta",
				"sequence_number": seq,
				"item_id":         msgID,
				"output_index":    messageOutputIndex(),
				"content_index":   0,
				"delta":           contentStr,
				"logprobs":        []any{},
			})
		}

		rawToolCalls, _ := delta["tool_calls"].([]any)
		for _, rawToolCall := range rawToolCalls {
			tc, ok := rawToolCall.(map[string]any)
			if !ok {
				continue
			}
			idxFloat, _ := tc["index"].(float64)
			upstreamIndex := int(idxFloat)
			call, exists := toolCalls[upstreamIndex]
			if !exists {
				outputIndex := messageOutputIndex()
				if messageStarted {
					outputIndex++
				}
				outputIndex += len(toolOrder)
				callID, _ := tc["id"].(string)
				if callID == "" {
					callID = "call_" + randomString(12)
				}
				fn, _ := tc["function"].(map[string]any)
				name, _ := fn["name"].(string)
				call = map[string]any{
					"output_index": outputIndex,
					"item_id":      "fc_" + callID,
					"call_id":      callID,
					"name":         name,
					"arguments":    "",
					"done":         false,
				}
				toolCalls[upstreamIndex] = call
				toolOrder = append(toolOrder, upstreamIndex)
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    outputIndex,
					"item":            responseFunctionCallItem(call["item_id"].(string), "in_progress", "", callID, name, toolNameMappings),
				})
			}
			fn, _ := tc["function"].(map[string]any)
			if name, _ := fn["name"].(string); name != "" {
				call["name"] = name
			}
			if argDelta, _ := fn["arguments"].(string); argDelta != "" {
				call["arguments"] = call["arguments"].(string) + argDelta
				seq++
				emitSSEEvent(w, flusher, "response.function_call_arguments.delta", map[string]any{
					"type":            "response.function_call_arguments.delta",
					"sequence_number": seq,
					"item_id":         call["item_id"],
					"output_index":    call["output_index"],
					"delta":           argDelta,
				})
			}
		}

		if usage, ok := chunk["usage"].(map[string]any); ok {
			totalUsage = usage
		}
		if finishReason == "stop" || finishReason == "length" || finishReason == "tool_calls" || finishReason == "function_call" || finishReason == "content_filter" {
			terminalFinishSeen = true
			if finishReason == "length" {
				isIncomplete = true
				incompleteReason = "max_output_tokens"
			}
			emitReasoningDone()
			if !messageStarted && len(toolCalls) == 0 {
				idx := messageOutputIndex()
				seq++
				emitSSEEvent(w, flusher, "response.output_item.added", map[string]any{
					"type":            "response.output_item.added",
					"sequence_number": seq,
					"output_index":    idx,
					"item":            map[string]any{"id": msgID, "type": "message", "status": "in_progress", "content": []any{}, "role": "assistant"},
				})
				seq++
				emitSSEEvent(w, flusher, "response.content_part.added", map[string]any{
					"type":            "response.content_part.added",
					"sequence_number": seq,
					"item_id":         msgID,
					"output_index":    idx,
					"content_index":   0,
					"part":            map[string]any{"type": "output_text", "annotations": []any{}, "logprobs": []any{}, "text": ""},
				})
				messageStarted = true
			}
			emitMessageDone()
			for _, idx := range toolOrder {
				emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
			}
		}
	}

	if !terminalFinishSeen {
		isIncomplete = true
		if incompleteReason == "" {
			incompleteReason = "stream_ended_early"
		}
		log.Printf("[responses stream incomplete] model=%q reason=%s message_started=%t tool_calls=%d", model, incompleteReason, messageStarted, len(toolOrder))
	}

	emitReasoningDone()
	emitMessageDone()
	if terminalFinishSeen {
		for _, idx := range toolOrder {
			emitToolCallDone(toolCalls[idx]["output_index"].(int), toolCalls[idx])
		}
	}

	output := []any{}
	if reasoningStarted {
		output = append(output, reasoningItem("completed"))
	}
	if messageStarted {
		output = append(output, messageItem("completed"))
	}
	for _, idx := range toolOrder {
		call := toolCalls[idx]
		args, _ := call["arguments"].(string)
		normalizedArgs, err := normalizeToolCallArguments(args)
		if err != nil {
			itemID, _ := call["item_id"].(string)
			callID, _ := call["call_id"].(string)
			name, _ := call["name"].(string)
			logStreamToolCallArgumentsValidationFailure("responsesStreamHandler.output", itemID, callID, name, args, call["output_index"].(int), err)
			isIncomplete = true
			if incompleteReason == "" {
				incompleteReason = "tool_call_arguments_incomplete"
			}
			continue
		}
		call["arguments"] = normalizedArgs
		itemStatus := "completed"
		if !terminalFinishSeen {
			itemStatus = "in_progress"
		}
		output = append(output, responseFunctionCallItem(
			call["item_id"].(string),
			itemStatus,
			normalizedArgs,
			call["call_id"].(string),
			call["name"].(string),
			toolNameMappings,
		))
	}

	responseStatus := "completed"
	incompleteDetails := any(nil)
	if isIncomplete {
		responseStatus = "incomplete"
		reason := incompleteReason
		if reason == "" {
			reason = "max_output_tokens"
		}
		incompleteDetails = map[string]any{"reason": reason}
	}
	completedResponse := map[string]any{
		"id":                 responseID,
		"object":             "response",
		"created_at":         createdAt,
		"status":             responseStatus,
		"background":         false,
		"error":              nil,
		"incomplete_details": incompleteDetails,
		"model":              model,
		"output":             output,
	}
	if len(tools) > 0 {
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		completedResponse["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		completedResponse["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}

	usage := map[string]any{}
	if len(totalUsage) > 0 {
		if v, ok := totalUsage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := totalUsage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := totalUsage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := totalUsage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := totalUsage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := totalUsage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	completedResponse["usage"] = usage

	if len(totalUsage) > 0 {
		pt, _ := getFloat(totalUsage, "prompt_tokens", "input_tokens")
		ct, _ := getFloat(totalUsage, "completion_tokens", "output_tokens")
		tt := pt + ct
		if tt > 0 {
			recordTokenUsage(model, int64(pt), int64(ct), int64(tt))
		}
	}

	emitSSEEvent(w, flusher, "response."+responseStatus, map[string]any{
		"type":     "response." + responseStatus,
		"response": completedResponse,
	})

	if flusher != nil {
		flusher.Flush()
	}
}

func convertChatToResponses(chatBody []byte, model string, tools []Tool, toolChoice any, toolNameMappings map[string]ResponseToolNameMapping) []byte {
	var chat struct {
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content          string     `json:"content"`
				ReasoningContent string     `json:"reasoning_content"`
				Reasoning        string     `json:"reasoning"`
				ToolCalls        []ToolCall `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(chatBody, &chat); err != nil {
		log.Printf("Warning: convertChatToResponses unmarshal failed: %v", err)
	}

	text := ""
	reasoning := ""
	finishReason := ""
	var toolCalls []ToolCall
	if len(chat.Choices) > 0 {
		text = chat.Choices[0].Message.Content
		reasoning = chat.Choices[0].Message.ReasoningContent
		if reasoning == "" {
			reasoning = chat.Choices[0].Message.Reasoning
		}
		toolCalls = chat.Choices[0].Message.ToolCalls
		finishReason = chat.Choices[0].FinishReason
	}

	status := "completed"
	if finishReason == "length" {
		status = "incomplete"
	}

	responses := map[string]any{
		"id":                 chat.ID,
		"object":             "response",
		"status":             status,
		"background":         false,
		"error":              nil,
		"incomplete_details": nil,
		"model":              model,
		"created_at":         chat.Created,
	}
	if len(tools) > 0 {
		// 回显时使用 Responses tools 形态
		rawTools := make([]any, 0, len(tools))
		for _, t := range tools {
			rawTools = append(rawTools, map[string]any{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		responses["tools"] = convertChatToolsToResponses(rawTools)
	}
	if toolChoice != nil {
		responses["tool_choice"] = convertChatToolChoiceToResponses(toolChoice)
	}
	outputID := "msg_" + chat.ID + "_0"
	output := []any{}
	if reasoning != "" {
		output = append(output, map[string]any{
			"id":                "rs_" + chat.ID,
			"type":              "reasoning",
			"encrypted_content": "",
			"summary":           []any{map[string]any{"type": "summary_text", "text": reasoning}},
		})
	}
	// 有文本时输出 message；仅有 tool_calls 时不注入空 message（与流式路径一致）
	if text != "" || len(toolCalls) == 0 {
		output = append(output, map[string]any{
			"id":     outputID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []any{map[string]any{
				"type":        "output_text",
				"text":        text,
				"annotations": []any{},
				"logprobs":    []any{},
			}},
		})
	}
	for _, tc := range toolCalls {
		output = append(output, responseFunctionCallItem("fc_"+tc.ID, "completed", tc.Function.Arguments, tc.ID, tc.Function.Name, toolNameMappings))
	}
	responses["output"] = output
	usage := map[string]any{}
	if chat.Usage != nil {
		if v, ok := chat.Usage["prompt_tokens"]; ok {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["prompt_tokens_details"]; ok {
			usage["input_tokens_details"] = v
		} else {
			usage["input_tokens_details"] = map[string]any{"cached_tokens": 0}
		}
		if v, ok := chat.Usage["completion_tokens"]; ok {
			usage["output_tokens"] = v
		}
		if v, ok := chat.Usage["completion_tokens_details"]; ok {
			usage["output_tokens_details"] = v
		}
		if v, ok := chat.Usage["total_tokens"]; ok {
			usage["total_tokens"] = v
		}
		if v, ok := chat.Usage["input_tokens"]; ok && usage["input_tokens"] == nil {
			usage["input_tokens"] = v
		}
		if v, ok := chat.Usage["output_tokens"]; ok && usage["output_tokens"] == nil {
			usage["output_tokens"] = v
		}
	}
	// Always ensure total_tokens is present
	if _, ok := usage["total_tokens"]; !ok {
		pt := float64(0)
		ct := float64(0)
		if v, ok := usage["input_tokens"].(float64); ok {
			pt = v
		} else if v, ok := usage["input_tokens"].(int64); ok {
			pt = float64(v)
		}
		if v, ok := usage["output_tokens"].(float64); ok {
			ct = v
		} else if v, ok := usage["output_tokens"].(int64); ok {
			ct = float64(v)
		}
		usage["total_tokens"] = pt + ct
	}
	// 确保 usage 字段完整
	if _, ok := usage["input_tokens"]; !ok {
		usage["input_tokens"] = float64(0)
	}
	if _, ok := usage["output_tokens"]; !ok {
		usage["output_tokens"] = float64(0)
	}
	responses["usage"] = usage

	// 非流式 Responses API 直接返回 response 对象，不包成 SSE 事件外壳
	result, _ := json.Marshal(responses)
	return result
}

func emitSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, data map[string]any) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling SSE event: %v", err)
		return
	}
	w.Write([]byte("event: " + event + "\n"))
	w.Write([]byte("data: " + string(jsonData) + "\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

// ======================== Admin 管理页面 ========================

func reloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	fetched, err := fetchModels()
	if err == nil && len(fetched) > 0 {
		modelMu.Lock()
		modelsCache = fetched
		modelsLoaded = true
		modelMu.Unlock()
		log.Printf("模型列表已刷新: %d 个模型", len(fetched))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"models":    len(modelsCache),
		"upstreams": getConfiguredUpstreamCount(),
	})
}

func adminConfigHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configMu.RLock()
		cfg := AppConfig{
			ModelAlias:         modelAlias,
			ReasoningEffortMap: reasoningEffortMap,
			Upstreams:          map[string]*UpstreamConfig{},
			DefaultUpstream:    defaultUpstreamName,
		}
		for name, upstream := range upstreamCfgs {
			cfg.Upstreams[name] = cloneUpstreamConfig(upstream)
		}
		configMu.RUnlock()
		socks5Mu.RLock()
		cfg.Socks5Proxies = socks5Proxies
		cfg.ActiveSocks5 = activeSocks5
		socks5Mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		// 附带上游模型列表供管理面板下拉框使用
		modelMu.RLock()
		availableModels := modelsCache
		modelMu.RUnlock()
		if availableModels == nil {
			availableModels = []ModelInfo{}
		}
		availableModelsByUpstream := groupModelsByUpstream(availableModels)
		resp := map[string]any{
			"model_alias":                  cfg.ModelAlias,
			"reasoning_effort_map":         cfg.ReasoningEffortMap,
			"socks5_proxies":               cfg.Socks5Proxies,
			"active_socks5":                cfg.ActiveSocks5,
			"upstreams":                    cfg.Upstreams,
			"default_upstream":             cfg.DefaultUpstream,
			"available_models":             availableModels,
			"available_models_by_upstream": availableModelsByUpstream,
		}
		json.NewEncoder(w).Encode(resp)
	case http.MethodPost:
		var cfg AppConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, `{"error":"Invalid JSON"}`, http.StatusBadRequest)
			return
		}
		normalizeConfig(&cfg)
		if err := saveConfig(configPath, cfg); err != nil {
			http.Error(w, `{"error":"Failed to save config"}`, http.StatusInternalServerError)
			return
		}
		upstreamsChanged := applyConfig(cfg)
		// 仅上游连接配置变化时重新拉取模型列表（模型映射/推理/代理保存跳过）
		if upstreamsChanged && getConfiguredUpstreamCount() > 0 {
			if models, err := fetchModels(); err == nil {
				modelMu.Lock()
				modelsCache = models
				modelsLoaded = true
				modelMu.Unlock()
				log.Printf("上游模型已更新: %d 个模型", len(models))
			} else {
				log.Printf("拉取上游模型失败: %v", err)
			}
		}
		if debugMode {
			log.Printf("Config updated: aliases=%d, effort_map=%d, upstreams=%d default=%s upstreams_changed=%v", len(cfg.ModelAlias), len(cfg.ReasoningEffortMap), len(cfg.Upstreams), cfg.DefaultUpstream, upstreamsChanged)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminStatsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tokenStatsMu.Lock()
		data, err := json.Marshal(tokenStats)
		tokenStatsMu.Unlock()
		if err != nil {
			http.Error(w, `{"error":"marshal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodDelete:
		tokenStatsMu.Lock()
		tokenStats = &TokenStatsData{Models: map[string]*ModelStats{}, Daily: &DailyStats{Date: getToday(), Models: map[string]*ModelStats{}}}
		statsDate = getToday()
		tokenStatsMu.Unlock()
		saveTokenStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminHTML))
}

func renderLoginPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(adminLoginHTML))
	if msg != "" {
		w.Write([]byte("<script>document.addEventListener('DOMContentLoaded',function(){var m=document.getElementById('login-msg');if(m){m.textContent='" + msg + "';m.style.display='block'}})</script>"))
	}
}

const adminLoginHTML = `<!DOCTYPE html>
<html lang="zh" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 — LLM Gateway</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{--bg:#f4f6fa;--surface:#fff;--border:#e2e6ed;--text:#1a1d26;--text-sec:#6a7180;--accent:#6c8aff;--accent-hover:#5a78f0;--radius:12px;--radius-sm:8px;--font:'Noto Sans SC',system-ui,-apple-system,sans-serif;--mono:'JetBrains Mono',Consolas,monospace}
[data-theme="dark"]{--bg:#0c0e14;--surface:#14161e;--border:#252835;--text:#e8eaf0;--text-sec:#8b90a5;--accent:#6c8aff;--accent-hover:#5a78f0}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,rgba(108,138,255,.04) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,rgba(61,214,140,.03) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:400px;width:100%;position:relative;z-index:1}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:36px 32px 32px}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:20px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12px;color:var(--text-sec);margin-top:2px}
.subtitle{font-size:13px;color:var(--text-sec);margin-bottom:28px;margin-top:4px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:500;color:var(--text-sec);margin-bottom:6px;letter-spacing:.3px}
.field input{width:100%;padding:10px 14px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:14px;font-family:var(--mono);background:var(--surface);color:var(--text);transition:border-color .15s,box-shadow .15s}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(108,138,255,.1)}
.msg{display:none;background:rgba(240,96,96,.1);color:#d64545;padding:10px 14px;border-radius:var(--radius-sm);margin-bottom:16px;font-size:13px;text-align:center;border:1px solid rgba(240,96,96,.2)}
[data-theme="dark"] .msg{color:#f06060}
.btn{width:100%;padding:10px;border:none;border-radius:var(--radius-sm);font-size:14px;font-weight:600;cursor:pointer;font-family:var(--font);background:var(--accent);color:#fff;transition:background .15s}
.btn:hover{background:var(--accent-hover)}
.theme-bar{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
.theme-toggle{background:transparent;border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:13px;color:var(--text-sec);font-family:var(--font);transition:all .15s}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}
@media(max-width:500px){.card{padding:24px 20px}}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="theme-bar">
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">管理面板</div>
</div>
</div>
<button class="theme-toggle" onclick="toggleTheme()">☀</button>
</div>
<div class="subtitle">请输入管理密码以继续</div>
<div class="msg" id="login-msg"></div>
<form method="post" action="/login">
<div class="field">
<label for="pwd">密码</label>
<input id="pwd" name="password" type="password" placeholder="输入管理密码" autocomplete="current-password" required>
</div>
<button class="btn" type="submit">登录</button>
</form>
</div>
</div>
<script>
(function(){var t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark')}})();
function toggleTheme(){var d=document.documentElement;var n=d.getAttribute('data-theme')==='dark'?'light':'dark';if(n==='dark')d.setAttribute('data-theme','dark');else d.removeAttribute('data-theme');localStorage.setItem('theme',n);document.querySelector('.theme-toggle').textContent=n==='dark'?'🌙':'☀'}
</script>
</body>
</html>`

const adminHTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLM Gateway 管理面板</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #f4f6fa;
  --surface: #ffffff;
  --surface-2: #f0f2f7;
  --border: #e2e6ed;
  --border-light: #d0d4df;
  --text: #1a1d26;
  --text-sec: #6a7180;
  --text-ter: #9ca3b0;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.08);
  --accent-hover: #5a78f0;
  --green: #22a85a;
  --green-dim: rgba(34,168,90,.08);
  --green-hover: #1d9850;
  --orange: #d9600a;
  --orange-dim: rgba(217,96,10,.08);
  --orange-hover: #c45507;
  --red: #dc2626;
  --red-dim: rgba(220,38,38,.08);
  --radius: 12px;
  --radius-sm: 8px;
  --font: 'Noto Sans SC', system-ui, -apple-system, sans-serif;
  --mono: 'JetBrains Mono', Consolas, monospace;
  --glow-a: rgba(108,138,255,.03);
  --glow-b: rgba(61,214,140,.02);
  --stats-total-bg: #f0f2f7;
}
[data-theme="dark"] {
  --bg: #0c0e14;
  --surface: #14161e;
  --surface-2: #1a1d27;
  --border: #252835;
  --border-light: #2e3142;
  --text: #e8eaf0;
  --text-sec: #8b90a5;
  --text-ter: #5c6080;
  --accent: #6c8aff;
  --accent-dim: rgba(108,138,255,.12);
  --accent-hover: #5a78f0;
  --green: #3dd68c;
  --green-dim: rgba(61,214,140,.12);
  --green-hover: #30c47a;
  --orange: #f0a050;
  --orange-dim: rgba(240,160,80,.12);
  --orange-hover: #e09040;
  --red: #f06060;
  --red-dim: rgba(240,96,96,.12);
  --glow-a: rgba(108,138,255,.04);
  --glow-b: rgba(61,214,140,.03);
  --stats-total-bg: var(--surface-2);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;min-height:100vh}
body::before{content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(ellipse at 30% 20%,var(--glow-a) 0%,transparent 50%),radial-gradient(ellipse at 70% 80%,var(--glow-b) 0%,transparent 50%);pointer-events:none;z-index:0}
.container{max-width:1020px;margin:0 auto;padding:32px 24px;position:relative;z-index:1}
header{display:flex;align-items:flex-end;gap:16px;margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border);justify-content:space-between}
.logo{display:flex;align-items:center;gap:10px}
.logo-mark{width:36px;height:36px;background:linear-gradient(135deg,var(--accent),#8b6cff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:20px;color:#fff;flex-shrink:0}
.logo-text{font-size:22px;font-weight:700;letter-spacing:-.5px;background:linear-gradient(135deg,var(--text),var(--text-sec));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.logo-sub{font-size:12.5px;color:var(--text-ter);margin-bottom:2px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:22px 24px;transition:border-color .2s}
.card:hover{border-color:var(--border-light)}
.card h2{font-size:13px;font-weight:600;margin-bottom:16px;letter-spacing:.2px;display:flex;align-items:center;gap:8px;color:var(--text-sec);text-transform:uppercase}
.card h2 .dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.config-grid{display:grid;grid-template-columns:2fr 3fr;gap:16px;margin-top:16px}
.config-grid .card{margin-bottom:0}
.full-row{grid-column:1/-1}
.form-group{margin-bottom:14px}
.form-group:last-child{margin-bottom:0}
.form-group label{display:block;font-size:11.5px;font-weight:500;color:var(--text-ter);margin-bottom:5px;letter-spacing:.4px;text-transform:uppercase}
.form-group input[type="text"],.form-group input[type="url"],.form-group input[type="password"],.form-group textarea,.form-group select,.m-select{width:100%;padding:8px 12px;border:1px solid var(--border);border-radius:var(--radius-sm);font-size:13px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.form-group input:focus,.form-group textarea:focus,.form-group select:focus,.m-select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim)}
.form-group .hint{font-size:11px;color:var(--text-ter);margin-top:4px;line-height:1.4}
.actions{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.btn{padding:8px 16px;border-radius:var(--radius-sm);font-size:12.5px;font-weight:500;cursor:pointer;border:none;transition:all .15s;font-family:var(--font);white-space:nowrap}
.btn-primary{background:var(--accent-dim);color:var(--accent)}
.btn-primary:hover{background:var(--accent);color:#fff}
.btn-default{background:var(--surface-2);color:var(--text-sec);border:1px solid var(--border)}
.btn-default:hover{border-color:var(--border-light);color:var(--text)}
.btn-success{background:var(--green-dim);color:var(--green)}
.btn-success:hover{background:var(--green);color:#fff}
.btn-warning{background:var(--orange-dim);color:var(--orange)}
.btn-warning:hover{background:var(--orange);color:#fff}
.btn-danger{background:var(--red-dim);color:var(--red)}
.btn-danger:hover{background:var(--red);color:#fff}
.tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.tbl th{text-align:left;font-weight:500;color:var(--text-ter);padding:8px 10px;border-bottom:1px solid var(--border);font-size:11px;letter-spacing:.4px;text-transform:uppercase;white-space:nowrap}
.tbl td{padding:7px 10px;border-bottom:1px solid var(--border)}
.tbl tr:last-child td{border-bottom:none}
.tbl input,.tbl textarea{width:100%;padding:6px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;font-family:var(--mono);background:var(--surface-2);color:var(--text);transition:border-color .15s,box-shadow .15s}
.tbl textarea{min-height:72px;resize:vertical;line-height:1.4}
.tbl input:focus,.tbl textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px var(--accent-dim)}
.tbl .m-select{padding:6px 10px;font-size:12.5px}
.tbl th:last-child{width:52px}
.tbl td:last-child{white-space:nowrap;text-align:center}
#statsTable th:last-child{width:auto}
#statsTable td:last-child{text-align:left;white-space:nowrap}
.tbl .btn{padding:4px 10px;font-size:11px;white-space:nowrap}
#statsTable td:first-child{font-weight:500;color:var(--text)}
#statsTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#statsTable tbody tr:hover{background:var(--surface-2)}
#statsTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
#dailyTable th:last-child{width:auto}
#dailyTable td:last-child{text-align:left;white-space:nowrap}
#dailyTable td:first-child{font-weight:500;color:var(--text)}
#dailyTable td:not(:first-child){font-family:var(--mono);color:var(--text-sec);text-align:left}
#dailyTable tbody tr:hover{background:var(--surface-2)}
#dailyTable thead+tbody tr:last-child td{font-weight:600;color:var(--text);background:var(--stats-total-bg);border-top:1px solid var(--border-light)}
.stats-header{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.stats-header .btns{display:flex;gap:6px;align-items:center}
#toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:var(--radius-sm);font-size:13px;font-weight:500;color:#fff;opacity:0;transition:opacity .25s,transform .25s;z-index:999;transform:translateY(-8px);pointer-events:none;backdrop-filter:blur(8px)}
#toast.success{background:rgba(61,214,140,.85)}
#toast.error{background:rgba(240,96,96,.85)}
#toast.show{opacity:1;transform:translateY(0)}
.empty-hint{color:var(--text-ter);font-size:13px;padding:28px;text-align:center}
.think-row{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;transition:border-color .15s}
.think-row:hover{border-color:var(--border-light)}
.think-row input[type="checkbox"]{width:16px;height:16px;accent-color:var(--accent);cursor:pointer}
.think-row label{font-size:13px;font-weight:500;cursor:pointer;margin:0;color:var(--text)}
.think-row .hint{font-size:11px;color:var(--text-ter);margin:0 0 0 auto;white-space:nowrap}
@media(max-width:700px){.config-grid{grid-template-columns:1fr}.container{padding:16px 12px}header{flex-direction:column;align-items:flex-start;gap:8px}}
.theme-toggle{background:var(--surface-2);border:1px solid var(--border);border-radius:var(--radius-sm);padding:6px 12px;cursor:pointer;font-size:18px;display:flex;align-items:center;justify-content:center;transition:all .15s;color:var(--text-sec);flex-shrink:0;line-height:1}
.theme-toggle:hover{border-color:var(--border-light);color:var(--text)}
</style>
</head>
<body>
<div class="container">
<header>
<div class="logo">
<div class="logo-mark">⌨</div>
<div>
<div class="logo-text">LLM Gateway</div>
<div class="logo-sub">通用 LLM 代理网关</div>
</div>
</div>
<div style="display:flex;align-items:center;gap:8px">
<button class="theme-toggle" onclick="toggleTheme()" title="切换主题">☀</button>
<form method="post" action="/logout" style="margin:0"><button class="theme-toggle" type="submit" title="退出登录" style="font-size:14px">退出</button></form>
</div>
</header>

<div class="card">
<div class="stats-header">
<h2><span class="dot" style="background:var(--green)"></span>Token 统计</h2>
<div class="btns">
<button class="btn btn-success" onclick="reloadConfig()">刷新</button>
<button class="btn btn-danger" onclick="resetStats()">清空统计</button>
<span id="resetStatus" style="font-size:11px;color:var(--text-ter)"></span>
</div>
</div>
<div id="statsContent" style="font-size:12.5px">
<div class="empty-hint">加载中...</div>
</div>
</div>

<div class="card full-row">
<div class="card">
<h2><span class="dot" style="background:var(--green)"></span>多上游配置</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="upstreamTable">
<thead><tr><th style="width:14%">名称</th><th style="width:28%">Base URL</th><th style="width:18%">API Key（每行一个）</th><th style="width:14%">接口类型</th><th style="width:18%">自定义模型</th><th style="width:8%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="form-group">
<label>默认上游</label>
<select id="defaultUpstream" class="m-select" style="width:100%" onchange="defaultUpstream=this.value;collectAliases();renderAliasTable()"></select>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addUpstreamRow()">添加上游</button>
<button class="btn btn-success" onclick="saveConfig('上游配置')">保存上游</button>
</div>
</div>


<div class="config-grid">
<div class="card">
<h2><span class="dot" style="background:var(--orange)"></span>推理力度映射</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="effortTable">
<thead><tr><th style="width:35%">请求值</th><th style="width:42%">映射值</th><th style="width:23%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addEffortRow()">添加映射</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>

<div class="card">
<h2><span class="dot" style="background:var(--accent)"></span>模型映射</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="aliasTable">
<thead><tr><th style="width:24%">别名（请求名）</th><th style="width:20%">上游</th><th style="width:28%">实际模型（上游名）</th><th style="width:16%">启用思维链</th><th style="width:12%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addAliasRow()">添加别名</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>

<div class="card full-row">
<h2><span class="dot" style="background:var(--accent)"></span>SOCKS5 代理</h2>
<div style="margin-bottom:12px">
<table class="tbl" id="socks5Table">
<thead><tr><th style="width:25%">名称</th><th style="width:28%">地址</th><th style="width:17%">用户名</th><th style="width:17%">密码</th><th style="width:13%"></th></tr></thead>
<tbody></tbody>
</table>
</div>
<div class="form-group">
<label>启用代理</label>
<select id="activeSocks5" class="m-select">
<option value="">直连（不使用代理）</option>
</select>
</div>
<div class="actions">
<button class="btn btn-primary" onclick="addSocks5Row()">添加代理</button>
<button class="btn btn-success" onclick="saveConfig()">保存全部</button>
</div>
</div>
</div>
</div>
<div id="toast"></div>
<script>
let aliasData={},effortData={},modelListByUpstream={},upstreamData={},defaultUpstream='',socks5Data=[];
function toggleTheme(){const d=document.documentElement;const cur=d.getAttribute('data-theme');const next=cur==='dark'?null:'dark';if(next)d.setAttribute('data-theme',next);else d.removeAttribute('data-theme');localStorage.setItem('theme',next||'light');document.querySelector('.theme-toggle').textContent=next==='dark'?'🌙':'☀'}
(function(){const t=localStorage.getItem('theme');if(t==='dark'){document.documentElement.setAttribute('data-theme','dark');document.addEventListener('DOMContentLoaded',()=>{const b=document.querySelector('.theme-toggle');if(b)b.textContent='🌙'})}})();
function reloadConfig(){const sy=window.scrollY;fetch('/api/reload',{method:'POST'}).then(r=>r.json()).then(d=>{showToast('会话已刷新，模型 '+d.models+' 个','success')}).catch(()=>{}).finally(()=>{loadConfig();loadStats();setTimeout(()=>window.scrollTo(0,sy),100)})}
function apiTypeSelectHtml(selected){const v=selected||'openai';return '<select data-field="api_type" class="m-select"><option value="openai"'+(v==='openai'?' selected':'')+'>OpenAI</option><option value="anthropic"'+(v==='anthropic'?' selected':'')+'>Anthropic</option><option value="openai-responses"'+(v==='openai-responses'?' selected':'')+'>Responses</option></select>'}
function buildModelMap(list){const grouped={};(list||[]).forEach(m=>{const owner=(m&&m.owned_by?String(m.owned_by):'default').trim()||'default';const id=m&&m.id?String(m.id):'';if(!id)return;if(!grouped[owner])grouped[owner]=[];grouped[owner].push(id)});Object.keys(grouped).forEach(k=>{grouped[k]=Array.from(new Set(grouped[k])).sort()});return grouped}
function normalizeAliasData(){const next={};Object.keys(aliasData||{}).forEach(k=>{const raw=aliasData[k];if(typeof raw==='object'&&raw){next[k]={target_model:raw.target_model||'',upstream:raw.upstream||'',with_reasoning:!!raw.with_reasoning}}else{next[k]={target_model:typeof raw==='string'?raw:'',upstream:'',with_reasoning:false}}});aliasData=next}
function normalizeUpstreamData(cfg){upstreamData=cfg.upstreams||{};defaultUpstream=(cfg.default_upstream||defaultUpstream||'').trim();if(!defaultUpstream||!upstreamData[defaultUpstream])defaultUpstream=Object.keys(upstreamData).sort()[0]||''}
async function loadConfig(){const sy=window.scrollY;try{const r=await fetch('/api/config');const cfg=await r.json();aliasData=cfg.model_alias||{};normalizeAliasData();effortData=cfg.reasoning_effort_map||{};socks5Data=cfg.socks5_proxies||[];normalizeUpstreamData(cfg);if(cfg.available_models_by_upstream&&Object.keys(cfg.available_models_by_upstream).length){modelListByUpstream={};Object.keys(cfg.available_models_by_upstream).forEach(k=>{modelListByUpstream[k]=(cfg.available_models_by_upstream[k]||[]).map(m=>typeof m==='string'?m:(m&&m.id?m.id:'')).filter(Boolean);modelListByUpstream[k]=Array.from(new Set(modelListByUpstream[k])).sort()})}else if(cfg.available_models&&cfg.available_models.length){modelListByUpstream=buildModelMap(cfg.available_models)}else{try{const mr=await fetch('/v1/models');const md=await mr.json();modelListByUpstream=buildModelMap(md.data||[])}catch(e){modelListByUpstream={}}}
renderUpstreamTable();renderAliasTable();renderEffortTable();renderSocks5Table();document.getElementById('activeSocks5').value=cfg.active_socks5||'';setTimeout(()=>window.scrollTo(0,sy),0)}catch(e){showToast('失败: '+e.message,'error')}}
function renderUpstreamTable(){const tb=document.querySelector('#upstreamTable tbody');const ks=Object.keys(upstreamData).sort();if(!ks.length){tb.innerHTML='<tr><td colspan="6" class="empty-hint">暂无上游配置</td></tr>';renderDefaultUpstreamSelect();return}tb.innerHTML=ks.map(name=>{const up=upstreamData[name]||{};return '<tr><td><input value="'+esc(name)+'" data-field="name" placeholder="例如: main"></td><td><input value="'+esc(up.base_url||'')+'" data-field="base_url" placeholder="https://example.com/v1"></td><td><textarea data-field="api_key" placeholder="每行一个 key">'+esc(up.api_key||'')+'</textarea></td><td>'+apiTypeSelectHtml(up.api_type)+'</td><td><input value="'+esc((up.custom_models||[]).join(','))+'" data-field="custom_models" placeholder="gpt-4o-mini,gpt-4.1"></td><td><button class="btn btn-danger" onclick="delUpstream(this)">删除</button></td></tr>'}).join('');renderDefaultUpstreamSelect()}
function addUpstreamRow(){collectUpstreams();const tb=document.querySelector('#upstreamTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" data-field="name" placeholder="例如: main"></td><td><input value="" data-field="base_url" placeholder="https://example.com/v1"></td><td><textarea data-field="api_key" placeholder="每行一个 key"></textarea></td><td>'+apiTypeSelectHtml('openai')+'</td><td><input value="" data-field="custom_models" placeholder="gpt-4o-mini,gpt-4.1"></td><td><button class="btn btn-danger" onclick="delUpstream(this)">删除</button></td></tr>')}
function delUpstream(btn){collectAliases();const row=btn.closest('tr');const ni=row.querySelector('[data-field="name"]');if(ni&&ni.value&&upstreamData[ni.value.trim()])delete upstreamData[ni.value.trim()];row.remove();if(!Object.keys(upstreamData).length)document.querySelector('#upstreamTable tbody').innerHTML='<tr><td colspan="6" class="empty-hint">暂无上游配置</td></tr>';renderDefaultUpstreamSelect();renderAliasTable()}
function collectUpstreams(){const r={};document.querySelectorAll('#upstreamTable tbody tr').forEach(tr=>{const name=(tr.querySelector('[data-field="name"]')||{}).value?.trim()||'';const baseURL=(tr.querySelector('[data-field="base_url"]')||{}).value?.trim()||'';if(!name||!baseURL)return;const apiKey=(tr.querySelector('[data-field="api_key"]')||{}).value?.trim()||'';const apiType=(tr.querySelector('[data-field="api_type"]')||{}).value||'openai';const customRaw=(tr.querySelector('[data-field="custom_models"]')||{}).value?.trim()||'';const up={base_url:baseURL,api_type:apiType};if(apiKey)up.api_key=apiKey;if(customRaw)up.custom_models=customRaw.split(',').map(s=>s.trim()).filter(Boolean);r[name]=up});upstreamData=r;if(!upstreamData[defaultUpstream])defaultUpstream=Object.keys(upstreamData).sort()[0]||'';return r}
function renderDefaultUpstreamSelect(){const sel=document.getElementById('defaultUpstream');const names=Object.keys(upstreamData).sort();const cur=(defaultUpstream||sel.value||'').trim();sel.innerHTML='<option value="">-- 选择默认上游 --</option>'+names.map(name=>'<option value="'+esc(name)+'"'+(cur===name?' selected':'')+'>'+esc(name)+'</option>').join('');if(cur&&upstreamData[cur])sel.value=cur;else if(defaultUpstream&&upstreamData[defaultUpstream])sel.value=defaultUpstream;else sel.value=names[0]||'';defaultUpstream=sel.value||''}
function modelsForUpstream(name){const resolved=(name||defaultUpstream||'').trim();return modelListByUpstream[resolved]||[]}
function upstreamSelectHtml(selected){const names=Object.keys(upstreamData).sort();let h='<select data-field="upstream" class="m-select" onchange="onAliasUpstreamChange(this)">';h+='<option value="">默认上游</option>';for(const name of names){h+='<option value="'+esc(name)+'"'+(selected===name?' selected':'')+'>'+esc(name)+'</option>'}h+='</select>';return h}
function modelSelectHtml(selected,upstreamName){const models=modelsForUpstream(upstreamName);let h='<select data-field="val" class="m-select">';h+='<option value="">-- 选择模型 --</option>';let found=!selected;for(const m of models){if(selected===m)found=true;h+='<option value="'+esc(m)+'"'+(selected===m?' selected':'')+'>'+esc(m)+'</option>'}if(selected&&!found)h+='<option value="'+esc(selected)+'" selected>'+esc(selected)+' (自定义)</option>';h+='</select>';return h}
function renderAliasTable(){const tb=document.querySelector('#aliasTable tbody');const ks=Object.keys(aliasData);if(!ks.length){tb.innerHTML='<tr><td colspan="5" class="empty-hint">暂无别名配置</td></tr>';return}tb.innerHTML=ks.map(k=>{const entry=aliasData[k]||{target_model:'',upstream:'',with_reasoning:false};return '<tr><td><input value="'+esc(k)+'" data-field="key"></td><td>'+upstreamSelectHtml(entry.upstream||'')+'</td><td data-model-cell="1">'+modelSelectHtml(entry.target_model||'',entry.upstream||'')+'</td><td><input type="checkbox" data-field="with_reasoning"'+(entry.with_reasoning?' checked':'')+'></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>'}).join('')}
function onAliasUpstreamChange(sel){const row=sel.closest('tr');const holder=row.querySelector('[data-model-cell]');const current=row.querySelector('[data-field="val"]');const currentVal=current?current.value.trim():'';holder.innerHTML=modelSelectHtml(currentVal,sel.value)}
function addAliasRow(){collectUpstreams();const tb=document.querySelector('#aliasTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: gpt-5.5" data-field="key"></td><td>'+upstreamSelectHtml('')+'</td><td data-model-cell="1">'+modelSelectHtml('', '')+'</td><td><input type="checkbox" data-field="with_reasoning"></td><td><button class="btn btn-danger" onclick="delAlias(this)">删除</button></td></tr>')}
function delAlias(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&aliasData[ki.value])delete aliasData[ki.value];row.remove();if(!Object.keys(aliasData).length)document.querySelector('#aliasTable tbody').innerHTML='<tr><td colspan="5" class="empty-hint">暂无别名配置</td></tr>'}
function collectAliases(){const r={};document.querySelectorAll('#aliasTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),u=tr.querySelector('[data-field="upstream"]'),v=tr.querySelector('[data-field="val"]'),w=tr.querySelector('[data-field="with_reasoning"]');if(k&&k.value.trim()){const aliasKey=k.value.trim();let targetModel=v?v.value.trim():'';const upstreamName=u?u.value.trim():'';const withReasoning=w?w.checked:false;if(!targetModel&&(upstreamName||withReasoning))targetModel=aliasKey;if(targetModel||upstreamName||withReasoning){r[aliasKey]={target_model:targetModel,upstream:upstreamName,with_reasoning:withReasoning}}}});aliasData=r;return r}






function renderEffortTable(){const tb=document.querySelector('#effortTable tbody');const ks=Object.keys(effortData);if(!ks.length){tb.innerHTML='<tr><td colspan="3" class="empty-hint">暂无映射配置</td></tr>';return}tb.innerHTML=ks.map(k=>'<tr><td><input value="'+esc(k)+'" data-field="key"></td><td><input value="'+esc(effortData[k])+'" data-field="val"></td><td><button class="btn btn-danger" onclick="delEffort(this)">删除</button></td></tr>').join('')}
function addEffortRow(){const tb=document.querySelector('#effortTable tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';tb.insertAdjacentHTML('beforeend','<tr><td><input value="" placeholder="例如: low" data-field="key"></td><td><input value="" placeholder="例如: high" data-field="val"></td><td><button class="btn btn-danger" onclick="delEffort(this)">删除</button></td></tr>')}
function delEffort(btn){const row=btn.closest('tr');const ki=row.querySelector('[data-field="key"]');if(ki&&ki.value&&effortData[ki.value])delete effortData[ki.value];row.remove();if(!Object.keys(effortData).length)document.querySelector('#effortTable tbody').innerHTML='<tr><td colspan="3" class="empty-hint">暂无映射配置</td></tr>'}
function collectEfforts(){const r={};document.querySelectorAll('#effortTable tbody tr').forEach(tr=>{const k=tr.querySelector('[data-field="key"]'),v=tr.querySelector('[data-field="val"]');if(k&&k.value.trim())r[k.value.trim()]=v?v.value.trim():''});effortData=r;return r}
function renderSocks5Table(){const tb=document.querySelector('#socks5Table tbody');if(!socks5Data.length){tb.innerHTML='<tr><td colspan="5" class="empty-hint">暂无代理配置</td></tr>';return}tb.innerHTML=socks5Data.map((p,i)=>'<tr><td><input value="'+esc(p.name||'')+'" data-field="name"></td><td><input value="'+esc(p.addr)+'" data-field="addr" placeholder="例如: 127.0.0.1:1080"></td><td><input value="'+esc(p.username||'')+'" data-field="username"></td><td><input value="'+esc(p.password||'')+'" data-field="password" type="password"></td><td><button class="btn btn-danger" onclick="delSocks5('+i+')">删除</button></td></tr>').join('');renderSocks5Select()}
function addSocks5Row(){const tb=document.querySelector('#socks5Table tbody');if(tb.querySelector('.empty-hint'))tb.innerHTML='';socks5Data.push({addr:'',name:''});renderSocks5Table()}
function delSocks5(i){socks5Data.splice(i,1);renderSocks5Table()}
function collectSocks5(){const r=[];document.querySelectorAll('#socks5Table tbody tr').forEach(tr=>{const a=tr.querySelector('[data-field="addr"]');if(a&&a.value.trim())r.push({addr:a.value.trim(),name:(tr.querySelector('[data-field="name"]')||{}).value?.trim()||'',username:(tr.querySelector('[data-field="username"]')||{}).value?.trim()||'',password:(tr.querySelector('[data-field="password"]')||{}).value?.trim()||''})});socks5Data=r;return r}
function renderSocks5Select(){const sel=document.getElementById('activeSocks5');const cur=sel.value;sel.innerHTML='<option value="">直连（不使用代理）</option>';socks5Data.forEach(p=>{if(p.addr){const label=p.name?p.name+' ('+p.addr+')':p.addr;const opt=document.createElement('option');opt.value=p.addr;opt.textContent=label;sel.appendChild(opt)}});if(socks5Data.length>=1){const opt=document.createElement('option');opt.value='__rate_limit_switch__';opt.textContent='限流切换（429 后切换，含直连）';sel.appendChild(opt);const opt2=document.createElement('option');opt2.value='__rate_limit_switch_no_direct__';opt2.textContent='限流切换（429 后切换，不含直连）';sel.appendChild(opt2)}if(socks5Data.length>=2){const opt=document.createElement('option');opt.value='__round_robin__';opt.textContent='轮询（每次请求切换）';sel.appendChild(opt)}sel.value=cur;if(!sel.value)sel.value='';}
async function saveConfig(section){collectUpstreams();defaultUpstream=(document.getElementById('defaultUpstream').value||defaultUpstream||'').trim();collectAliases();collectEfforts();collectSocks5();const cfg={model_alias:aliasData,reasoning_effort_map:effortData,socks5_proxies:socks5Data,active_socks5:document.getElementById('activeSocks5').value,upstreams:upstreamData,default_upstream:defaultUpstream||''};const label=section||'配置';try{const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(cfg)});if(!r.ok)throw new Error(await r.text());showToast(label+'已保存','success');loadConfig()}catch(e){showToast(label+'保存失败: '+e.message,'error')}}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function showToast(msg,t){const e=document.getElementById('toast');e.textContent=msg;e.className=t+' show';clearTimeout(e._tid);e._tid=setTimeout(()=>e.classList.remove('show'),2500)}
async function resetStats(){if(!confirm('确认清空所有 Token 统计？\n此操作不可撤销。'))return;const s=document.getElementById('resetStatus');s.textContent='清空中...';try{const r=await fetch('/api/stats',{method:'DELETE'});if(!r.ok)throw new Error(await r.text());document.getElementById('statsContent').innerHTML='<div class="empty-hint">暂无数据</div>';s.textContent='已清空';setTimeout(()=>s.textContent='',2000)}catch(e){s.textContent='失败: '+e.message}}
async function loadStats(){try{const r=await fetch('/api/stats');const d=await r.json();const ms=d.models||{};const ks=Object.keys(ms);const dm=d.daily?d.daily.models||{}:{};const dk=Object.keys(dm);let h='';if(d.daily&&d.daily.date){h+='<div style="margin-bottom:16px;padding:10px 14px;background:var(--accent);color:#fff;border-radius:8px;font-size:13px">📊 今日统计 ('+esc(d.daily.date)+')：请求 '+fmt(d.daily.total_requests)+' 次</div>'}if(dk.length>0){h+='<h3 style="font-size:14px;font-weight:600;margin:0 0 8px">今日模型用量</h3><table class="tbl" id="dailyTable"><thead><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总计 Token</th></tr></thead><tbody>';let dr=0,dp=0,dc=0,dt=0;for(const k of dk){const m=dm[k];if(!m)continue;h+='<tr><td>'+esc(k)+'</td><td>'+fmt(m.request_count)+'</td><td>'+fmt(m.prompt_tokens)+'</td><td>'+fmt(m.completion_tokens)+'</td><td>'+fmt(m.total_tokens)+'</td></tr>';dr+=m.request_count;dp+=m.prompt_tokens;dc+=m.completion_tokens;dt+=m.total_tokens}h+='<tr style="font-weight:600"><td>今日合计</td><td>'+fmt(dr)+'</td><td>'+fmt(dp)+'</td><td>'+fmt(dc)+'</td><td>'+fmt(dt)+'</td></tr>';h+='</tbody></table><hr style="border:none;border-top:1px solid var(--border);margin:20px 0">'}h+='<h3 style="font-size:14px;font-weight:600;margin:0 0 8px">累计统计</h3><table class="tbl" id="statsTable"><thead><tr><th>模型</th><th>请求数</th><th>输入 Token</th><th>输出 Token</th><th>总计 Token</th></tr></thead><tbody>';if(!ks.length){h+='<tr><td colspan="5" class="empty-hint">暂无数据</td></tr>'}else{let tr=0,pt=0,ct=0,tt=0;for(const k of ks){const m=ms[k];h+='<tr><td>'+esc(k)+'</td><td>'+fmt(m.request_count)+'</td><td>'+fmt(m.prompt_tokens)+'</td><td>'+fmt(m.completion_tokens)+'</td><td>'+fmt(m.total_tokens)+'</td></tr>';tr+=m.request_count;pt+=m.prompt_tokens;ct+=m.completion_tokens;tt+=m.total_tokens}h+='<tr style="font-weight:600"><td>累计总计</td><td>'+fmt(tr)+'</td><td>'+fmt(pt)+'</td><td>'+fmt(ct)+'</td><td>'+fmt(tt)+'</td></tr>'}h+='</tbody></table>';document.getElementById('statsContent').innerHTML=h}catch(e){document.getElementById('statsContent').innerHTML='<div class="empty-hint">加载失败</div>'}}
function fmt(n){return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g,',')}window.onload=function(){loadConfig();loadStats()};setInterval(loadStats,5000);document.addEventListener('visibilitychange',function(){if(!document.hidden)loadStats()});
</script>
</body>
</html>`

// ======================== Main ========================

func main() {
	flag.StringVar(&port, "port", "8000", "服务端口")
	flag.StringVar(&configPath, "config", "config.json", "配置文件路径")
	flag.StringVar(&adminPassword, "password", "123456", "管理面板密码（留空则不启用登录验证）")
	flag.BoolVar(&debugMode, "debug", false, "启用调试日志")
	flag.Parse()

	cfg := loadConfig(configPath)
	applyConfig(cfg)
	if err := saveConfig(configPath, cfg); err != nil {
		log.Printf("警告: 无法保存配置: %v", err)
	}

	loadTokenStats()
	log.Printf("配置已从 %s 加载", configPath)
	models, err := fetchModels()
	if err != nil {
		log.Printf("警告: 无法获取模型列表: %v", err)
	} else {
		modelMu.Lock()
		modelsCache = models
		modelsLoaded = true
		modelMu.Unlock()
		log.Printf("已加载 %d 个模型:", len(models))
		for _, m := range models {
			log.Printf("  - %s", m.ID)
		}
	}
	log.Printf("LLM Gateway")
	log.Printf("===================")
	log.Printf("端口:     %s", port)
	log.Printf("上游:     %d 个（默认: %s）", getConfiguredUpstreamCount(), getDefaultUpstreamName())
	log.Printf("模型：  %d 个模型已加载", len(getModelIDs()))
	log.Printf("别名：  %d", len(modelAlias))

	if adminPassword != "" {
		log.Printf("管理面板: http://localhost:%s/ （密码认证已启用）", port)
	} else {
		log.Printf("管理面板: http://localhost:%s/ （无密码）", port)
	}
	log.Printf("===================")
	http.HandleFunc("/v1/chat/completions", chatCompletionsHandler)
	http.HandleFunc("/v1/responses", responsesHandler)
	http.HandleFunc("/v1/messages", anthropicMessagesHandler)
	http.HandleFunc("/v1/models", listModelsHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/api/config", requireAuth(adminConfigHandler))
	http.HandleFunc("/api/stats", requireAuth(adminStatsHandler))
	http.HandleFunc("/api/reload", requireAuth(reloadHandler))
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			requireAuth(adminPageHandler)(w, r)
			return
		}
		http.NotFound(w, r)
	})
	addr := ":" + port
	log.Printf("服务器启动在 %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}
