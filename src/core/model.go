package core

// CurrentSchema 是 state.json 的最新结构版本。
const CurrentSchema = 1

type Settings struct {
	AutoReapply     bool   `json:"auto_reapply"`
	ReapplyInterval int    `json:"reapply_interval"`
	RenewDays       int    `json:"renew_days"`
	RenewHour       int    `json:"renew_hour"`
	HealthInterval  int    `json:"health_interval"`
	LogLevel        string `json:"log_level"`
	AccessLog       bool   `json:"access_log"`
	DefaultCertID   string `json:"default_cert_id"`

	// DNS 传播校验
	DNSResolvers []string `json:"dns_resolvers"`  // 自定义递归 DNS，留空则用系统 DNS + 国内公共 DNS
	DNSCheckMode string   `json:"dns_check_mode"` // auto（默认）| strict | recursive
	DNSWaitSec   int      `json:"dns_wait_sec"`   // 传播检查最长等待秒数，默认 180
}

func DefaultSettings() Settings {
	return Settings{
		AutoReapply: true, ReapplyInterval: 60, RenewDays: 30,
		RenewHour: 3, HealthInterval: 30, LogLevel: "INFO", AccessLog: true,
		DNSCheckMode: "auto", DNSWaitSec: 180,
	}
}

type Forward struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Protocol       string `json:"protocol"`
	ExternalPort   int    `json:"external_port"`
	InternalPort   int    `json:"internal_port"`
	InternalClient string `json:"internal_client"`
	LeaseTime      int    `json:"lease_time"`
	CreatedAt      string `json:"created_at"`
}

type GatewayFingerprint struct {
	IP    string `json:"ip"`
	Model string `json:"model"`
}

type TLSConfig struct {
	CertID       string   `json:"cert_id"`
	MinVersion   string   `json:"min_version"`
	HSTS         bool     `json:"hsts"`
	RedirectHTTP bool     `json:"redirect_http"`
	ALPN         []string `json:"alpn,omitempty"`
}

type Listener struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"` // http | https | tcp
	Bind      string    `json:"bind"`
	TLS       TLSConfig `json:"tls"`
	Enabled   bool      `json:"enabled"`
	CreatedAt string    `json:"created_at"`
}

type Route struct {
	ID               string            `json:"id"`
	ListenerID       string            `json:"listener_id"`
	Name             string            `json:"name"`
	Domains          []string          `json:"domains"`
	PathPrefix       string            `json:"path_prefix"`
	MatchType        string            `json:"match_type"` // prefix | exact
	Backend          string            `json:"backend"`
	StripPrefix      bool              `json:"strip_prefix"`
	VerifyBackendTLS bool              `json:"verify_backend_tls"`
	Websocket        bool              `json:"websocket"`
	TimeoutMS        int               `json:"timeout_ms"`
	RequestHeaders   map[string]string `json:"request_headers,omitempty"`
	CertID           string            `json:"cert_id"`
	Enabled          bool              `json:"enabled"`
	Description      string            `json:"description"`
	CreatedAt        string            `json:"created_at"`
}

type ACMEMeta struct {
	CA           string `json:"ca"`
	DirectoryURL string `json:"directory_url,omitempty"`
	Challenge    string `json:"challenge"`
	ProviderID   string `json:"provider_id"`
	ManualDNS    bool   `json:"manual_dns"`
	AccountID    string `json:"account_id"`
	KeyType      string `json:"key_type"`
	AutoRenew    bool   `json:"auto_renew"`
	LastRenewAt  string `json:"last_renew_at,omitempty"`
	NextRenewAt  string `json:"next_renew_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	FailCount    int    `json:"fail_count"`
}

type Certificate struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Source        string    `json:"source"` // manual | fnos | acme | selfsigned
	PrimaryDomain string    `json:"primary_domain"`
	SANs          []string  `json:"sans"`
	Issuer        string    `json:"issuer"`
	NotBefore     string    `json:"not_before"`
	NotAfter      string    `json:"not_after"`
	Fingerprint   string    `json:"fingerprint"`
	CertPath      string    `json:"cert_path"` // 相对 DataDir
	KeyPath       string    `json:"key_path"`  // 相对 DataDir
	ACME          *ACMEMeta `json:"acme,omitempty"`
	CreatedAt     string    `json:"created_at"`
	UpdatedAt     string    `json:"updated_at"`
}

type ACMEAccount struct {
	ID           string `json:"id"`
	CA           string `json:"ca"`
	DirectoryURL string `json:"directory_url,omitempty"`
	Email        string `json:"email"`
	KeyPath      string `json:"key_path"` // 相对 DataDir，位于 secrets/
	EABKID       string `json:"eab_kid,omitempty"`
	EABHMAC      string `json:"eab_hmac,omitempty"`
	CreatedAt    string `json:"created_at"`
}

type DNSProvider struct {
	ID            string `json:"id"`
	Type          string `json:"type"` // alidns | dnspod | cloudflare | manual
	Name          string `json:"name"`
	CredentialRef string `json:"credential_ref"` // secrets/dns/<id>.json
	AccountHint   string `json:"account_hint,omitempty"`
	LastCheckAt   string `json:"last_check_at,omitempty"`
	LastCheckOK   bool   `json:"last_check_ok"`
	LastCheckMsg  string `json:"last_check_msg,omitempty"`
	ZoneCount     int    `json:"zone_count"`
	CreatedAt     string `json:"created_at"`
}

type TXTRecord struct {
	Domain string `json:"domain"`
	Value  string `json:"value"`
}

type ACMEOrder struct {
	ID           string      `json:"id"`
	CertID       string      `json:"cert_id"`
	Domains      []string    `json:"domains"`
	Status       string      `json:"status"` // pending | waiting_dns | validating | issuing | done | failed | canceled
	Challenge    string      `json:"challenge"`
	ProviderID   string      `json:"provider_id"`
	AccountID    string      `json:"account_id,omitempty"`
	CA           string      `json:"ca,omitempty"`
	DirectoryURL string      `json:"directory_url,omitempty"`
	KeyType      string      `json:"key_type,omitempty"`
	AutoRenew    bool        `json:"auto_renew,omitempty"`
	ManualTXT    []TXTRecord `json:"manual_txt,omitempty"`
	Logs         []string    `json:"logs"`
	Error        string      `json:"error,omitempty"`
	CreatedAt    string      `json:"created_at"`
	UpdatedAt    string      `json:"updated_at"`
}

type State struct {
	SchemaVersion      int                `json:"schema_version"`
	Settings           Settings           `json:"settings"`
	Forwards           []Forward          `json:"forwards"`
	GatewayFingerprint GatewayFingerprint `json:"gateway_fingerprint"`
	Listeners          []Listener         `json:"listeners"`
	Routes             []Route            `json:"routes"`
	Certificates       []Certificate      `json:"certificates"`
	ACMEAccounts       []ACMEAccount      `json:"acme_accounts"`
	DNSProviders       []DNSProvider      `json:"dns_providers"`
	ACMEOrders         []ACMEOrder        `json:"acme_orders"`
}

func NewState() State {
	st := State{
		SchemaVersion: CurrentSchema,
		Settings:      DefaultSettings(),
	}
	st.Normalize()
	return st
}

// Normalize 保证切片非 nil，并把设置收敛到合法范围。
func (s *State) Normalize() {
	if s.Forwards == nil {
		s.Forwards = []Forward{}
	}
	if s.Listeners == nil {
		s.Listeners = []Listener{}
	}
	if s.Routes == nil {
		s.Routes = []Route{}
	}
	if s.Certificates == nil {
		s.Certificates = []Certificate{}
	}
	if s.ACMEAccounts == nil {
		s.ACMEAccounts = []ACMEAccount{}
	}
	if s.DNSProviders == nil {
		s.DNSProviders = []DNSProvider{}
	}
	if s.ACMEOrders == nil {
		s.ACMEOrders = []ACMEOrder{}
	}
	if s.Settings.ReapplyInterval < 15 {
		s.Settings.ReapplyInterval = 15
	}
	if s.Settings.ReapplyInterval > 3600 {
		s.Settings.ReapplyInterval = 3600
	}
	if s.Settings.RenewDays < 7 {
		s.Settings.RenewDays = 7
	}
	if s.Settings.RenewDays > 60 {
		s.Settings.RenewDays = 60
	}
	if s.Settings.RenewHour < 0 || s.Settings.RenewHour > 23 {
		s.Settings.RenewHour = 3
	}
	if s.Settings.HealthInterval < 10 {
		s.Settings.HealthInterval = 10
	}
	if s.Settings.LogLevel == "" {
		s.Settings.LogLevel = "INFO"
	}
}
