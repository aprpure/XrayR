package api

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

// Sentinel errors returned by panel clients when a resource is unchanged
// (HTTP 304). Controllers match them with errors.Is.
var (
	ErrUserNotModified = errors.New("users not modified")
	ErrNodeNotModified = errors.New("node not modified")
	ErrRuleNotModified = errors.New("rules not modified")
)

// Config API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	NodeType            string  `mapstructure:"NodeType"`
	EnableVless         bool    `mapstructure:"EnableVless"`
	VlessFlow           string  `mapstructure:"VlessFlow"`
	Timeout             int     `mapstructure:"Timeout"`
	SpeedLimit          float64 `mapstructure:"SpeedLimit"`
	DeviceLimit         int     `mapstructure:"DeviceLimit"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
	DisableCustomConfig bool    `mapstructure:"DisableCustomConfig"`
}

// NodeStatus Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	AcceptProxyProtocol bool
	Authority           string
	NodeType            string // Must be V2ray, Trojan, and Shadowsocks
	NodeID              int
	Port                uint32
	SpeedLimit          uint64 // Bps
	AlterID             uint16
	TransportProtocol   string
	FakeType            string
	Host                string
	Path                string
	EnableTLS           bool
	EnableSniffing      bool
	RouteOnly           bool
	EnableVless         bool
	VlessFlow           string
	CypherMethod        string
	ServerKey           string
	ServiceName         string
	Method              string
	Header              json.RawMessage
	HttpHeaders         map[string]*conf.StringList
	Headers             map[string]string
	NameServerConfig    []*conf.NameServerConfig
	EnableREALITY       bool
	REALITYConfig       *REALITYConfig
	Show                bool
	EnableTFO           bool
	Dest                string
	ProxyProtocolVer    uint64
	ServerNames         []string
	PrivateKey          string
	MinClientVer        string
	MaxClientVer        string
	MaxTimeDiff         uint64
	ShortIds            []string
	Xver                uint64
	Flow                string
	Security            string
	Key                 string
	RejectUnknownSni    bool
	Decryption          string // VLESS server-side decryption (Xboard encryption.decryption)
	HysteriaVersion     int    // Hysteria protocol version, xray-core supports v2 only
	UpMbps              int    // Hysteria bandwidth up (Mbps)
	DownMbps            int    // Hysteria bandwidth down (Mbps)
	Obfs                string // Hysteria obfs type (salamander)
	ObfsPassword        string // Hysteria obfs password
	PushInterval        int    // Panel-defined push interval in seconds (base_config.push_interval)
	PullInterval        int    // Panel-defined pull interval in seconds (base_config.pull_interval)
}

type UserInfo struct {
	UID         int
	Email       string
	UUID        string
	Passwd      string
	Port        uint32
	AlterID     uint16
	Method      string
	SpeedLimit  uint64 // Bps
	DeviceLimit int
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
	NodeType string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}

type REALITYConfig struct {
	Dest             string
	ProxyProtocolVer uint64
	ServerNames      []string
	PrivateKey       string
	MinClientVer     string
	MaxClientVer     string
	MaxTimeDiff      uint64
	ShortIds         []string
}
