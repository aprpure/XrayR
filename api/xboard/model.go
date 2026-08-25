package xboard

import (
	"encoding/json"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
)

// nodeConfig mirrors the JSON returned by Xboard's buildNodeConfig()
// (ServerService.php) for the protocols this client supports:
// vmess, vless, trojan, shadowsocks, hysteria.
type nodeConfig struct {
	// NodeID is populated by the caller (not part of the panel payload).
	NodeID int `json:"-"`

	Protocol   string `json:"protocol"`
	ListenIP   string `json:"listen_ip"`
	ServerPort int    `json:"server_port"`
	Host       string `json:"host"`
	Network    string `json:"network"`

	NetworkSettings struct {
		Path        string           `json:"path"`
		Host        string           `json:"host"`
		Headers     *json.RawMessage `json:"headers"`
		ServiceName string           `json:"serviceName"`
		Header      *json.RawMessage `json:"header"`
	} `json:"networkSettings"`

	BaseConfig struct {
		PushInterval int `json:"push_interval"`
		PullInterval int `json:"pull_interval"`
	} `json:"base_config"`

	Routes []route `json:"routes"`

	// vmess / vless / trojan: tls 0=none, 1=tls, 2=reality
	TLS int `json:"tls"`
	// vless
	Flow       string `json:"flow"`
	Decryption string `json:"decryption"`
	// tls_settings for tls mode; reality_settings are merged into it when tls==2
	TLSSettings struct {
		Dest       string `json:"dest"`
		Xver       uint64 `json:"xver,string"`
		Sni        string `json:"server_name"`
		ServerPort string `json:"server_port"`
		PrivateKey string `json:"private_key"`
		ShortId    string `json:"short_id"`
	} `json:"tls_settings"`

	// shadowsocks
	Cipher    string `json:"cipher"`
	Plugin    string `json:"plugin"`
	PluginOpt string `json:"plugin_opts"`
	ServerKey string `json:"server_key"`

	// hysteria
	Version      int    `json:"version"`
	ServerName   string `json:"server_name"`
	UpMbps       int    `json:"up_mbps"`
	DownMbps     int    `json:"down_mbps"`
	Obfs         string `json:"obfs"`
	ObfsPassword string `json:"obfs-password"`

	AcceptProxyProtocol bool `json:"accept_proxy_protocol"`
}

type route struct {
	Id          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value"`
}

type user struct {
	Id          int     `json:"id"`
	Uuid        string  `json:"uuid"`
	SpeedLimit  float64 `json:"speed_limit"`
	DeviceLimit int     `json:"device_limit"`
}

type usersResponse struct {
	Users []*user `json:"users"`
}

// parseDNSConfig extracts DNS route actions into xray name server config.
func (s *nodeConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
	for i := range s.Routes {
		if s.Routes[i].Action == "dns" {
			nameServerList = append(nameServerList, &conf.NameServerConfig{
				Address: &conf.Address{Address: net.ParseAddress(s.Routes[i].ActionValue)},
				Domains: s.Routes[i].Match,
			})
		}
	}

	return
}
