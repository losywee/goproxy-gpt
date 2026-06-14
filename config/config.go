package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

const DefaultPassword = "goproxy"

func dataDir() string {
	if d := os.Getenv("DATA_DIR"); d != "" {
		os.MkdirAll(d, 0755)
		return d + "/"
	}
	return ""
}

func ConfigFile() string { return dataDir() + "config.json" }

type Config struct {
	// WebUI 端口
	WebUIPort string

	// WebUI 密码 SHA256 哈希
	WebUIPasswordHash string

	// 代理池本地监听端口（随机轮换模式）
	ProxyPort string

	// 稳定代理端口（最低延迟模式）
	StableProxyPort string

	// SOCKS5 服务端口（随机轮换模式）
	SOCKS5Port string

	// 稳定 SOCKS5 端口（最低延迟模式）
	StableSOCKS5Port string

	// 国家过滤 HTTP 代理端口（随机轮换模式）
	CountryProxyPort string

	// 国家过滤 SOCKS5 代理端口（随机轮换模式）
	CountrySOCKS5Port string

	// 代理服务认证配置
	ProxyAuthEnabled      bool   // 是否启用代理认证（默认 false）
	ProxyAuthUsername     string // 代理认证用户名（默认 "proxy"）
	ProxyAuthPassword     string // 代理认证密码明文（用于 SOCKS5）
	ProxyAuthPasswordHash string // 代理认证密码 SHA256 哈希（用于 HTTP）

	// 地理过滤配置
	BlockedCountries      []string // 屏蔽的国家代码列表（如 ["CN", "RU"]，默认 ["CN"]）
	AllowedCountries      []string // 允许的国家代码列表（白名单，非空时优先于黑名单）
	CountryProxyCountries []string // 国家过滤代理端口使用的国家代码列表（为空时不提供代理）

	// SQLite 数据库路径
	DBPath string

	// ========== 池子容量配置 ==========
	PoolMaxSize        int     // 代理池总容量（默认100）
	PoolHTTPRatio      float64 // HTTP协议占比（默认0.5）
	PoolMinPerProtocol int     // 每协议最小保证（默认10）

	// ========== 延迟标准配置 ==========
	MaxLatencyMs          int // 标准模式最大延迟（默认2000ms）
	MaxLatencyEmergency   int // 紧急模式放宽延迟（默认3000ms）
	MaxLatencyHealthy     int // 健康模式严格延迟（默认1500ms）
	MaxLatencyDegradation int // 降级模式超宽松延迟（默认5000ms）

	// ========== 验证配置 ==========
	ValidateConcurrency int    // 验证并发数（默认300）
	ValidateTimeout     int    // 验证超时（秒）（默认8）
	ValidateURL         string // 验证目标 URL

	// ========== 健康检查配置 ==========
	HealthCheckInterval    int // 状态监控间隔（分钟）（默认5）
	HealthCheckBatchSize   int // 每批验证数量（默认20）
	HealthCheckConcurrency int // 批次内并发数（默认50）

	// ========== 优化配置 ==========
	OptimizeInterval    int     // 优化轮换间隔（分钟）（默认30）
	OptimizeConcurrency int     // 优化时并发数（默认100）
	ReplaceThreshold    float64 // 替换阈值（默认0.7，新代理需快30%）

	// ========== IP查询配置 ==========
	IPQueryRateLimit int // IP查询限流（次/秒）（默认10）

	// ========== 源管理配置 ==========
	SourceFailThreshold    int // 源降级阈值（默认3）
	SourceDisableThreshold int // 源禁用阈值（默认5）
	SourceCooldownMinutes  int // 源禁用冷却时间（默认30）
	CustomSources          []SourceConfig

	// ========== 自定义订阅代理配置 ==========
	CustomProxyMode       string // 代理使用模式：mixed / custom_only / free_only（默认 mixed）
	CustomPriority        bool   // 混用模式下订阅代理优先（默认 true）
	CustomFreePriority    bool   // 混用模式下免费代理优先（默认 false）
	CustomProbeInterval   int    // 禁用代理探测唤醒间隔（分钟，默认 10）
	CustomRefreshInterval int    // 默认订阅刷新间隔（分钟，默认 60）
	SingBoxPath           string // sing-box 二进制路径（默认 "sing-box"）
	SingBoxBasePort       int    // sing-box 本地端口起始（默认 20000）

	// ========== 兼容旧配置 ==========
	MaxResponseMs int // 已废弃，使用 MaxLatencyMs 替代
	MaxFailCount  int // 代理失败次数阈值
	MaxRetry      int // 请求失败后的重试次数
	FetchInterval int // 已废弃，由智能抓取器管理
	CheckInterval int // 已废弃，由 HealthCheckInterval 替代

	// 代理来源 URL（已废弃，内置多源）
	HTTPSourceURL   string
	SOCKS5SourceURL string
}

// SourceConfig 可编辑代理来源配置
type SourceConfig struct {
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
}

var (
	globalCfg *Config
	cfgMu     sync.RWMutex
)

func cloneConfig(cfg *Config) *Config {
	if cfg == nil {
		return nil
	}
	cloned := *cfg
	if cfg.BlockedCountries != nil {
		cloned.BlockedCountries = append([]string(nil), cfg.BlockedCountries...)
	}
	if cfg.AllowedCountries != nil {
		cloned.AllowedCountries = append([]string(nil), cfg.AllowedCountries...)
	}
	if cfg.CountryProxyCountries != nil {
		cloned.CountryProxyCountries = append([]string(nil), cfg.CountryProxyCountries...)
	}
	if cfg.CustomSources != nil {
		cloned.CustomSources = append([]SourceConfig(nil), cfg.CustomSources...)
	}
	return &cloned
}

// NormalizeCustomSources 规范化用户自定义来源，去重并只保留 http/socks5 协议。
func NormalizeCustomSources(sources []SourceConfig) []SourceConfig {
	seen := make(map[string]bool, len(sources))
	normalized := make([]SourceConfig, 0, len(sources))
	for _, source := range sources {
		url := strings.TrimSpace(source.URL)
		protocol := strings.TrimSpace(strings.ToLower(source.Protocol))
		if protocol == "socks4" {
			protocol = "socks5"
		}
		if url == "" || (protocol != "http" && protocol != "socks5") {
			continue
		}
		key := protocol + "\n" + url
		if seen[key] {
			continue
		}
		seen[key] = true
		normalized = append(normalized, SourceConfig{URL: url, Protocol: protocol})
	}
	return normalized
}

func normalizeCountryCodes(countries []string) []string {
	seen := make(map[string]bool, len(countries))
	normalized := make([]string, 0, len(countries))
	for _, country := range countries {
		country = strings.TrimSpace(strings.ToUpper(country))
		if country == "" || seen[country] {
			continue
		}
		seen[country] = true
		normalized = append(normalized, country)
	}
	return normalized
}

func parseCountryCodes(value string) []string {
	if value == "" {
		return nil
	}
	return normalizeCountryCodes(strings.Split(value, ","))
}

func listenAddress(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	if strings.HasPrefix(value, ":") {
		return value
	}
	return ":" + value
}

func passwordHash(plain string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(plain)))
}

func DefaultConfig() *Config {
	// 优先从环境变量 WEBUI_PASSWORD 读取密码，未设置时使用默认密码
	password := os.Getenv("WEBUI_PASSWORD")
	if password == "" {
		password = DefaultPassword
	}

	// 读取代理认证配置
	proxyAuthEnabled := os.Getenv("PROXY_AUTH_ENABLED") == "true"
	proxyAuthUsername := os.Getenv("PROXY_AUTH_USERNAME")
	if proxyAuthUsername == "" {
		proxyAuthUsername = "proxy"
	}
	proxyAuthPassword := os.Getenv("PROXY_AUTH_PASSWORD")
	proxyAuthHash := ""
	if proxyAuthPassword != "" {
		proxyAuthHash = passwordHash(proxyAuthPassword)
	}

	// 读取地理过滤配置
	blockedCountries := []string{"CN"} // 默认屏蔽中国大陆
	if blockedEnv := os.Getenv("BLOCKED_COUNTRIES"); blockedEnv != "" {
		// 支持逗号分隔的国家代码，如 "CN,RU,KP"
		blockedCountries = parseCountryCodes(blockedEnv)
	}

	// 读取白名单配置（白名单非空时优先于黑名单）
	allowedCountries := parseCountryCodes(os.Getenv("ALLOWED_COUNTRIES"))

	// 读取国家过滤代理配置
	countryProxyPort := listenAddress(os.Getenv("COUNTRY_PROXY_PORT"), ":7781")
	countrySOCKS5Port := listenAddress(os.Getenv("COUNTRY_SOCKS5_PORT"), ":7782")
	countryProxyCountries := parseCountryCodes(os.Getenv("COUNTRY_PROXY_COUNTRIES"))
	if len(countryProxyCountries) == 0 {
		countryProxyCountries = parseCountryCodes(os.Getenv("COUNTRY_FILTER_COUNTRIES"))
	}

	// 读取订阅代理配置
	customProxyMode := os.Getenv("CUSTOM_PROXY_MODE")
	if customProxyMode == "" {
		customProxyMode = "mixed"
	}
	singBoxPath := os.Getenv("SINGBOX_PATH")
	if singBoxPath == "" {
		singBoxPath = "sing-box"
	}

	return &Config{
		// 基础服务配置
		WebUIPort:         ":7778",
		WebUIPasswordHash: passwordHash(password),
		ProxyPort:         ":7777",
		StableProxyPort:   ":7776",
		SOCKS5Port:        ":7779",
		StableSOCKS5Port:  ":7780",
		CountryProxyPort:  countryProxyPort,
		CountrySOCKS5Port: countrySOCKS5Port,
		DBPath:            dataDir() + "proxy.db",

		// 代理认证配置
		ProxyAuthEnabled:      proxyAuthEnabled,
		ProxyAuthUsername:     proxyAuthUsername,
		ProxyAuthPassword:     proxyAuthPassword,
		ProxyAuthPasswordHash: proxyAuthHash,

		// 地理过滤配置
		BlockedCountries:      blockedCountries,
		AllowedCountries:      allowedCountries,
		CountryProxyCountries: countryProxyCountries,

		// 池子容量配置
		PoolMaxSize:        100, // 总容量
		PoolHTTPRatio:      0.3, // HTTP占30%
		PoolMinPerProtocol: 10,  // 每协议最少10个

		// 延迟标准配置
		MaxLatencyMs:          2500, // 标准2.5秒
		MaxLatencyEmergency:   4000, // 紧急4秒
		MaxLatencyHealthy:     2000, // 健康2秒
		MaxLatencyDegradation: 5000, // 降级5秒

		// 验证配置
		ValidateConcurrency: 300,
		ValidateTimeout:     10, // 从8秒增加到10秒
		ValidateURL:         "http://www.gstatic.com/generate_204",

		// 健康检查配置
		HealthCheckInterval:    5,  // 5分钟
		HealthCheckBatchSize:   20, // 每批20个
		HealthCheckConcurrency: 50, // 批次并发50

		// 优化配置
		OptimizeInterval:    30,  // 30分钟
		OptimizeConcurrency: 100, // 并发100
		ReplaceThreshold:    0.7, // 新代理需快30%

		// IP查询配置
		IPQueryRateLimit: 10, // 10次/秒

		// 源管理配置
		SourceFailThreshold:    3,  // 失败3次降级
		SourceDisableThreshold: 5,  // 失败5次禁用
		SourceCooldownMinutes:  30, // 禁用30分钟

		// 自定义订阅代理配置
		CustomProxyMode:       customProxyMode,
		CustomPriority:        true,
		CustomProbeInterval:   10,
		CustomRefreshInterval: 60,
		SingBoxPath:           singBoxPath,
		SingBoxBasePort:       20000,

		// 兼容旧配置
		MaxResponseMs:   5000,
		MaxFailCount:    3,
		MaxRetry:        3,
		FetchInterval:   30,
		CheckInterval:   10,
		HTTPSourceURL:   "https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/http.txt",
		SOCKS5SourceURL: "https://cdn.jsdelivr.net/gh/databay-labs/free-proxy-list/socks5.txt",
	}
}

// Load 从文件加载配置，文件不存在则用默认值
func Load() *Config {
	cfg := DefaultConfig()
	data, err := os.ReadFile(ConfigFile())
	if err == nil {
		var saved savedConfig
		if json.Unmarshal(data, &saved) == nil {
			// 池子配置
			if saved.PoolMaxSize > 0 {
				cfg.PoolMaxSize = saved.PoolMaxSize
			}
			if saved.PoolHTTPRatio > 0 && saved.PoolHTTPRatio <= 1 {
				cfg.PoolHTTPRatio = saved.PoolHTTPRatio
			}
			if saved.PoolMinPerProtocol > 0 {
				cfg.PoolMinPerProtocol = saved.PoolMinPerProtocol
			}

			// 延迟配置
			if saved.MaxLatencyMs > 0 {
				cfg.MaxLatencyMs = saved.MaxLatencyMs
			}
			if saved.MaxLatencyEmergency > 0 {
				cfg.MaxLatencyEmergency = saved.MaxLatencyEmergency
			}
			if saved.MaxLatencyHealthy > 0 {
				cfg.MaxLatencyHealthy = saved.MaxLatencyHealthy
			}

			// 验证配置
			if saved.ValidateConcurrency > 0 {
				cfg.ValidateConcurrency = saved.ValidateConcurrency
			}
			if saved.ValidateTimeout > 0 {
				cfg.ValidateTimeout = saved.ValidateTimeout
			}

			// 健康检查配置
			if saved.HealthCheckInterval > 0 {
				cfg.HealthCheckInterval = saved.HealthCheckInterval
			}
			if saved.HealthCheckBatchSize > 0 {
				cfg.HealthCheckBatchSize = saved.HealthCheckBatchSize
			}
			if saved.HealthCheckConcurrency > 0 {
				cfg.HealthCheckConcurrency = saved.HealthCheckConcurrency
			}

			// 优化配置
			if saved.OptimizeInterval > 0 {
				cfg.OptimizeInterval = saved.OptimizeInterval
			}
			if saved.OptimizeConcurrency > 0 {
				cfg.OptimizeConcurrency = saved.OptimizeConcurrency
			}
			if saved.ReplaceThreshold > 0 && saved.ReplaceThreshold <= 1 {
				cfg.ReplaceThreshold = saved.ReplaceThreshold
			}

			// IP 查询配置
			if saved.IPQueryRateLimit > 0 {
				cfg.IPQueryRateLimit = saved.IPQueryRateLimit
			}

			// 源管理配置
			if saved.SourceFailThreshold > 0 {
				cfg.SourceFailThreshold = saved.SourceFailThreshold
			}
			if saved.SourceDisableThreshold > 0 {
				cfg.SourceDisableThreshold = saved.SourceDisableThreshold
			}
			if saved.SourceCooldownMinutes > 0 {
				cfg.SourceCooldownMinutes = saved.SourceCooldownMinutes
			}
			if saved.CustomSources != nil {
				cfg.CustomSources = NormalizeCustomSources(saved.CustomSources)
			}

			// 兼容旧配置
			if saved.FetchInterval > 0 {
				cfg.FetchInterval = saved.FetchInterval
			}
			if saved.CheckInterval > 0 {
				cfg.CheckInterval = saved.CheckInterval
			}

			// 地理过滤配置（config.json 优先于环境变量）
			if saved.BlockedCountries != nil {
				cfg.BlockedCountries = normalizeCountryCodes(saved.BlockedCountries)
			}
			if saved.AllowedCountries != nil {
				cfg.AllowedCountries = normalizeCountryCodes(saved.AllowedCountries)
			}
			if saved.CountryProxyCountries != nil {
				cfg.CountryProxyCountries = normalizeCountryCodes(saved.CountryProxyCountries)
			}

			// 自定义订阅代理配置
			if saved.CustomProxyMode != "" {
				cfg.CustomProxyMode = saved.CustomProxyMode
			}
			if saved.CustomPriority != nil {
				cfg.CustomPriority = *saved.CustomPriority
			}
			if saved.CustomFreePriority != nil {
				cfg.CustomFreePriority = *saved.CustomFreePriority
			}
			if saved.CustomProbeInterval > 0 {
				cfg.CustomProbeInterval = saved.CustomProbeInterval
			}
			if saved.CustomRefreshInterval > 0 {
				cfg.CustomRefreshInterval = saved.CustomRefreshInterval
			}
			if saved.SingBoxPath != "" {
				cfg.SingBoxPath = saved.SingBoxPath
			}
			if saved.SingBoxBasePort > 0 {
				cfg.SingBoxBasePort = saved.SingBoxBasePort
			}
		}
	}
	cfgMu.Lock()
	globalCfg = cloneConfig(cfg)
	cfgMu.Unlock()
	return cloneConfig(cfg)
}

// Get 获取当前配置快照。调用方可以安全读取或修改返回值，不会和 Save 并发写入冲突。
func Get() *Config {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cloneConfig(globalCfg)
}

// savedConfig 持久化可调整的字段
type savedConfig struct {
	// 池子配置
	PoolMaxSize        int     `json:"pool_max_size"`
	PoolHTTPRatio      float64 `json:"pool_http_ratio"`
	PoolMinPerProtocol int     `json:"pool_min_per_protocol"`

	// 延迟配置
	MaxLatencyMs        int `json:"max_latency_ms"`
	MaxLatencyEmergency int `json:"max_latency_emergency"`
	MaxLatencyHealthy   int `json:"max_latency_healthy"`

	// 验证配置
	ValidateConcurrency int `json:"validate_concurrency"`
	ValidateTimeout     int `json:"validate_timeout"`

	// 健康检查配置
	HealthCheckInterval    int `json:"health_check_interval"`
	HealthCheckBatchSize   int `json:"health_check_batch_size"`
	HealthCheckConcurrency int `json:"health_check_concurrency,omitempty"`

	// 优化配置
	OptimizeInterval    int     `json:"optimize_interval"`
	OptimizeConcurrency int     `json:"optimize_concurrency,omitempty"`
	ReplaceThreshold    float64 `json:"replace_threshold"`

	// IP查询配置
	IPQueryRateLimit int `json:"ip_query_rate_limit,omitempty"`

	// 源管理配置
	SourceFailThreshold    int            `json:"source_fail_threshold,omitempty"`
	SourceDisableThreshold int            `json:"source_disable_threshold,omitempty"`
	SourceCooldownMinutes  int            `json:"source_cooldown_minutes,omitempty"`
	CustomSources          []SourceConfig `json:"custom_sources,omitempty"`

	// 地理过滤配置
	BlockedCountries      []string `json:"blocked_countries,omitempty"`
	AllowedCountries      []string `json:"allowed_countries,omitempty"`
	CountryProxyCountries []string `json:"country_proxy_countries,omitempty"`

	// 自定义订阅代理配置
	CustomProxyMode       string `json:"custom_proxy_mode,omitempty"`
	CustomPriority        *bool  `json:"custom_priority,omitempty"`
	CustomFreePriority    *bool  `json:"custom_free_priority,omitempty"`
	CustomProbeInterval   int    `json:"custom_probe_interval,omitempty"`
	CustomRefreshInterval int    `json:"custom_refresh_interval,omitempty"`
	SingBoxPath           string `json:"singbox_path,omitempty"`
	SingBoxBasePort       int    `json:"singbox_base_port,omitempty"`

	// 兼容旧配置
	FetchInterval int `json:"fetch_interval,omitempty"`
	CheckInterval int `json:"check_interval,omitempty"`
}

// Save 保存配置到文件，并更新内存配置
func Save(cfg *Config) error {
	cfgCopy := cloneConfig(cfg)
	if cfgCopy == nil {
		return fmt.Errorf("config is nil")
	}

	cfgMu.Lock()
	globalCfg = cfgCopy
	cfgMu.Unlock()

	customPriority := cfgCopy.CustomPriority
	customFreePriority := cfgCopy.CustomFreePriority
	data, err := json.MarshalIndent(savedConfig{
		PoolMaxSize:            cfgCopy.PoolMaxSize,
		PoolHTTPRatio:          cfgCopy.PoolHTTPRatio,
		PoolMinPerProtocol:     cfgCopy.PoolMinPerProtocol,
		MaxLatencyMs:           cfgCopy.MaxLatencyMs,
		MaxLatencyEmergency:    cfgCopy.MaxLatencyEmergency,
		MaxLatencyHealthy:      cfgCopy.MaxLatencyHealthy,
		ValidateConcurrency:    cfgCopy.ValidateConcurrency,
		ValidateTimeout:        cfgCopy.ValidateTimeout,
		HealthCheckInterval:    cfgCopy.HealthCheckInterval,
		HealthCheckBatchSize:   cfgCopy.HealthCheckBatchSize,
		HealthCheckConcurrency: cfgCopy.HealthCheckConcurrency,
		OptimizeInterval:       cfgCopy.OptimizeInterval,
		OptimizeConcurrency:    cfgCopy.OptimizeConcurrency,
		ReplaceThreshold:       cfgCopy.ReplaceThreshold,
		IPQueryRateLimit:       cfgCopy.IPQueryRateLimit,
		SourceFailThreshold:    cfgCopy.SourceFailThreshold,
		SourceDisableThreshold: cfgCopy.SourceDisableThreshold,
		SourceCooldownMinutes:  cfgCopy.SourceCooldownMinutes,
		CustomSources:          NormalizeCustomSources(cfgCopy.CustomSources),
		BlockedCountries:       normalizeCountryCodes(cfgCopy.BlockedCountries),
		AllowedCountries:       normalizeCountryCodes(cfgCopy.AllowedCountries),
		CountryProxyCountries:  normalizeCountryCodes(cfgCopy.CountryProxyCountries),
		CustomProxyMode:        cfgCopy.CustomProxyMode,
		CustomPriority:         &customPriority,
		CustomFreePriority:     &customFreePriority,
		CustomProbeInterval:    cfgCopy.CustomProbeInterval,
		CustomRefreshInterval:  cfgCopy.CustomRefreshInterval,
		SingBoxPath:            cfgCopy.SingBoxPath,
		SingBoxBasePort:        cfgCopy.SingBoxBasePort,
		FetchInterval:          cfgCopy.FetchInterval,
		CheckInterval:          cfgCopy.CheckInterval,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigFile(), data, 0644)
}

// CalculateSlots 根据配置计算各协议的槽位数
func (c *Config) CalculateSlots() (httpSlots, socks5Slots int) {
	httpSlots = int(float64(c.PoolMaxSize) * c.PoolHTTPRatio)
	socks5Slots = c.PoolMaxSize - httpSlots

	// 保证最小值
	if httpSlots < c.PoolMinPerProtocol {
		httpSlots = c.PoolMinPerProtocol
	}
	if socks5Slots < c.PoolMinPerProtocol {
		socks5Slots = c.PoolMinPerProtocol
	}

	return
}

// GetLatencyThreshold 根据池子状态返回合适的延迟阈值
func (c *Config) GetLatencyThreshold(poolStatus string) int {
	switch poolStatus {
	case "emergency":
		return c.MaxLatencyEmergency
	case "critical":
		return c.MaxLatencyEmergency
	case "warning":
		// warning状态使用紧急标准，加快填充速度
		return c.MaxLatencyEmergency
	case "healthy":
		return c.MaxLatencyHealthy
	default:
		return c.MaxLatencyMs
	}
}
