package xboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/wyx2685/XrayR/api"
)

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	path := c.configPath()

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags.get("node")).
		ForceContentType("application/json").
		Get(path)

	// Network errors take precedence over any status-code shortcuts.
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.APIHost+path, err)
	}
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.NodeNotModified)
	}

	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	// V2 endpoint just fell back to V1; re-issue the request against V1.
	if c.useV1.Load() && res.StatusCode() == 404 {
		return c.GetNodeInfo()
	}

	server := new(nodeConfig)
	if err := json.Unmarshal(res.Body(), server); err != nil {
		return nil, fmt.Errorf("parse node config failed: %s, \nError: %v", res.String(), err)
	}

	// update etag
	if etag := res.Header().Get("Etag"); etag != "" {
		c.eTags.set("node", etag)
	}

	if server.ServerPort == 0 {
		return nil, errors.New("server port must > 0")
	}
	if server.Protocol == "" {
		return nil, fmt.Errorf("invalid config: missing protocol")
	}
	// The panel tells us the real protocol; it must match the requested node type family.
	if !c.protocolMatches(server.Protocol) {
		return nil, fmt.Errorf("panel protocol %q does not match configured node type %q", server.Protocol, c.NodeType)
	}

	server.NodeID = c.NodeID
	c.resp.Store(server)

	switch server.Protocol {
	case "vmess", "vless":
		nodeInfo, err = c.parseV2rayNodeResponse(server)
	case "trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(server)
	case "shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(server)
	case "hysteria":
		nodeInfo, err = c.parseHysteriaNodeResponse(server)
	default:
		return nil, fmt.Errorf("unsupported panel protocol: %s", server.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}

	return nodeInfo, nil
}

// protocolMatches checks the panel-reported protocol is compatible with the
// locally configured NodeType. For the V2ray family the local EnableVless
// switch decides vless vs vmess (same semantics as the NewV2board client):
// NodeType=V2ray + EnableVless=true -> panel node must be vless.
func (c *APIClient) protocolMatches(protocol string) bool {
	local := strings.ToLower(nodeTypeForRequests(c.NodeType, c.EnableVless))
	switch local {
	case "vless":
		return protocol == "vless"
	case "v2ray", "vmess":
		return protocol == "vmess"
	default:
		return protocol == local
	}
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (*[]api.UserInfo, error) {
	var users []*user
	path := c.userPath()

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags.get("users")).
		ForceContentType("application/json").
		Get(path)

	// Network errors take precedence over any status-code shortcuts.
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.APIHost+path, err)
	}
	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, errors.New(api.UserNotModified)
	}

	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	// V2 endpoint just fell back to V1; re-issue the request against V1.
	if c.useV1.Load() && res.StatusCode() == 404 {
		return c.GetUserList()
	}

	// update etag
	if etag := res.Header().Get("Etag"); etag != "" {
		c.eTags.set("users", etag)
	}

	usersResp := new(usersResponse)
	if err := json.Unmarshal(res.Body(), usersResp); err != nil {
		return nil, fmt.Errorf("parse user list failed: %s, \nError: %v", res.String(), err)
	}
	users = usersResp.Users
	if len(users) == 0 {
		return nil, errors.New("users is null")
	}

	var deviceLimit int
	userList := make([]api.UserInfo, 0, len(users))
	for _, u := range users {
		ui := api.UserInfo{
			UID:  u.Id,
			UUID: u.Uuid,
		}
		// Local speed limit takes precedence over panel value. Mbps -> Bps
		if c.SpeedLimit > 0 {
			ui.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			ui.SpeedLimit = uint64(u.SpeedLimit * 1000000 / 8)
		}
		// Prefer local config
		if c.DeviceLimit > 0 {
			deviceLimit = c.DeviceLimit
		} else {
			deviceLimit = u.DeviceLimit
		}
		ui.DeviceLimit = deviceLimit
		ui.Email = fmt.Sprintf("%d@xboard.user", ui.UID)
		if c.NodeType == "Shadowsocks" || c.NodeType == "shadowsocks" {
			ui.Passwd = ui.UUID
		}

		userList = append(userList, ui)
	}

	return &userList, nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	v := c.resp.Load()
	if v == nil {
		// No node config fetched yet; only local rules apply.
		return &c.LocalRuleList, nil
	}
	routes := v.(*nodeConfig).Routes

	ruleList := c.LocalRuleList

	for i := range routes {
		if routes[i].Action == "block" {
			ruleList = append(ruleList, api.DetectRule{
				ID:      i,
				Pattern: regexp.MustCompile(strings.Join(routes[i].Match, "|")),
			})
		}
	}

	return &ruleList, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	var path string
	// json structure: {uid1: [u, d], uid2: [u, d], ...}
	data := make(map[int][]int64, len(*userTraffic))
	for _, traffic := range *userTraffic {
		data[traffic.UID] = []int64{traffic.Upload, traffic.Download}
	}

	if c.useV1.Load() {
		path = "/api/v1/server/UniProxy/push"
		res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
		_, err = c.parseResponse(res, path, err)
		if err != nil {
			return err
		}
		return nil
	}

	// V2 consolidated report: wrap traffic under the "traffic" key with auth injected in body
	payload := map[string]interface{}{
		"node_id": c.NodeID,
		"token":   c.Key,
		"traffic": data,
	}
	path = "/api/v2/server/report"
	res, err := c.client.R().SetBody(payload).ForceContentType("application/json").Post(path)
	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	if c.useV1.Load() && res.StatusCode() == 404 {
		return c.ReportUserTraffic(userTraffic)
	}

	return nil
}

// ReportNodeOnlineUsers reports online devices per user (alive IP list).
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	data := make(map[int][]string)
	for _, onlineuser := range *onlineUserList {
		// json structure: { UID1:["ip1","ip2"],UID2:["ip3","ip4"] }
		data[onlineuser.UID] = append(data[onlineuser.UID], onlineuser.IP)
	}

	var path string
	if c.useV1.Load() {
		path = "/api/v1/server/UniProxy/alive"
		res, err := c.client.R().SetBody(data).ForceContentType("application/json").Post(path)
		_, err = c.parseResponse(res, path, err)
		// 面板无对应接口时先不报错
		if err != nil {
			return nil
		}
		return nil
	}

	payload := map[string]interface{}{
		"node_id": c.NodeID,
		"token":   c.Key,
		"alive":   data,
	}
	path = "/api/v2/server/report"
	res, err := c.client.R().SetBody(payload).ForceContentType("application/json").Post(path)
	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return nil
	}
	if c.useV1.Load() && res.StatusCode() == 404 {
		return c.ReportNodeOnlineUsers(onlineUserList)
	}

	return nil
}

// ReportNodeStatus implements the API interface.
// Xboard receives status through ReportIllegal-free consolidated report; to keep
// parity with other clients we push status in its own V2 report / ignore on V1.
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	if c.useV1.Load() {
		// Legacy UniProxy has no status endpoint wired into XrayR's reporting flow
		return nil
	}
	payload := map[string]interface{}{
		"node_id": c.NodeID,
		"token":   c.Key,
		"status": map[string]interface{}{
			"cpu": nodeStatus.CPU,
			"mem": map[string]interface{}{"used": 0, "total": 0},
		},
	}
	path := "/api/v2/server/report"
	res, err := c.client.R().SetBody(payload).ForceContentType("application/json").Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseTrojanNodeResponse(s *nodeConfig) (*api.NodeInfo, error) {
	var (
		host   string
		header json.RawMessage
	)
	transportProtocol := func() string {
		if s.Network == "" {
			return "tcp"
		}
		return s.Network
	}()
	switch transportProtocol {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	}
	enableTLS, enableREALITY := tlsMode(s.TLS)

	realityConfig := buildREALITYConfig(s)

	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: transportProtocol,
		Path:              s.NetworkSettings.Path,
		EnableTLS:         enableTLS,
		Host:              host,
		Header:            header,
		ServiceName:       s.NetworkSettings.ServiceName,
		NameServerConfig:  s.parseDNSConfig(),
		EnableREALITY:     enableREALITY,
		REALITYConfig:     realityConfig,
		PushInterval:      s.BaseConfig.PushInterval,
		PullInterval:      s.BaseConfig.PullInterval,
		AcceptProxyProtocol: s.AcceptProxyProtocol,
	}
	if host == "" {
		nodeInfo.Host = s.Host
	}
	return nodeInfo, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseSSNodeResponse(s *nodeConfig) (*api.NodeInfo, error) {
	var header json.RawMessage

	if s.Plugin == "obfs" {
		// simple-obfs carried via plugin/plugin_opts; type comes from plugin_opts (http or tls)
		h := simplejson.New()
		h.Set("type", obfsType(s))
		path := obfsPath(s)
		h.SetPath([]string{"request", "path"}, path)
		header, _ = h.Encode()
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "tcp",
		CypherMethod:      s.Cipher,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
		PushInterval:      s.BaseConfig.PushInterval,
		PullInterval:      s.BaseConfig.PullInterval,
	}, nil
}

// obfsType extracts the simple-obfs mode from plugin_opts ("obfs=http;..." style).
// Defaults to http when unspecified.
func obfsType(s *nodeConfig) string {
	for _, part := range strings.Split(s.PluginOpt, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "obfs") {
			return strings.ToLower(kv[1])
		}
	}
	return "http"
}

func obfsPath(s *nodeConfig) string {
	path := "/"
	if p := s.NetworkSettings.Path; p != "" {
		if strings.HasPrefix(p, "/") {
			return p
		}
		return path + p
	}
	return path
}

// parseV2rayNodeResponse parse vmess/vless responses
func (c *APIClient) parseV2rayNodeResponse(s *nodeConfig) (*api.NodeInfo, error) {
	var (
		host          string
		header        json.RawMessage
		enableREALITY bool
	)
	dest := s.TLSSettings.Dest
	if dest == "" {
		dest = s.TLSSettings.Sni
	}
	realityconfig := api.REALITYConfig{
		Dest:             dest + ":" + s.TLSSettings.ServerPort,
		ProxyProtocolVer: s.TLSSettings.Xver,
		ServerNames:      []string{s.TLSSettings.Sni},
		PrivateKey:       s.TLSSettings.PrivateKey,
		ShortIds:         []string{s.TLSSettings.ShortId},
	}
	switch s.Network {
	case "ws":
		if s.NetworkSettings.Headers != nil {
			if httpHeader, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeader)
				host = b.Get("Host").MustString()
			}
		}
	case "tcp":
		if s.NetworkSettings.Header != nil {
			if httpHeader, err := s.NetworkSettings.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	case "httpupgrade", "xhttp":
		if s.NetworkSettings.Headers != nil {
			if httpHeaders, err := s.NetworkSettings.Headers.MarshalJSON(); err != nil {
				return nil, err
			} else {
				b, _ := simplejson.NewJson(httpHeaders)
				host = b.Get("Host").MustString()
			}
		}
		if s.NetworkSettings.Host != "" {
			host = s.NetworkSettings.Host
		}
	}
	if host == "" {
		host = s.NetworkSettings.Host
	}

	enableTLS, enableREALITY := tlsMode(s.TLS)

	// Vless vs vmess is decided by the local config switch (EnableVless),
	// mirroring the NewV2board client; panel protocol only breaks ties.
	isVless := func() bool {
		switch strings.ToLower(nodeTypeForRequests(c.NodeType, c.EnableVless)) {
		case "vless":
			return true
		default:
			return false
		}
	}()

	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		AlterID:           0,
		TransportProtocol: s.Network,
		EnableTLS:         enableTLS,
		Path:              s.NetworkSettings.Path,
		Host:              host,
		EnableVless:       isVless,
		VlessFlow:         s.Flow,
		ServiceName:       s.NetworkSettings.ServiceName,
		Header:            header,
		EnableREALITY:     enableREALITY,
		REALITYConfig:     &realityconfig,
		Decryption:        s.Decryption,
		NameServerConfig:  s.parseDNSConfig(),
		PushInterval:      s.BaseConfig.PushInterval,
		PullInterval:      s.BaseConfig.PullInterval,
		AcceptProxyProtocol: s.AcceptProxyProtocol,
	}, nil
}

// parseHysteriaNodeResponse parses hysteria node config. xray-core only supports
// hysteria v2; v1 nodes are rejected here.
func (c *APIClient) parseHysteriaNodeResponse(s *nodeConfig) (*api.NodeInfo, error) {
	if s.Version != 2 {
		return nil, fmt.Errorf("xray-core only supports hysteria v2, got version %d", s.Version)
	}
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              uint32(s.ServerPort),
		TransportProtocol: "hysteria",
		EnableTLS:         true, // hysteria always runs over TLS
		HysteriaVersion:   s.Version,
		UpMbps:            s.UpMbps,
		DownMbps:          s.DownMbps,
		Obfs:              s.Obfs,
		ObfsPassword:      s.ObfsPassword,
		Host:              s.Host,
		NameServerConfig:  s.parseDNSConfig(),
		PushInterval:      s.BaseConfig.PushInterval,
		PullInterval:      s.BaseConfig.PullInterval,
		AcceptProxyProtocol: s.AcceptProxyProtocol,
	}, nil
}

// tlsMode converts the panel's int TLS mode to (enableTLS, enableREALITY).
func tlsMode(tls int) (bool, bool) {
	switch tls {
	case 2:
		return true, true
	case 1:
		return true, false
	default:
		return false, false
	}
}

// buildREALITYConfig builds REALITY settings from merged reality/tls_settings.
// When tls==2 Xboard merges reality_settings into tls_settings server-side.
func buildREALITYConfig(s *nodeConfig) *api.REALITYConfig {
	if s.TLS != 2 {
		return nil
	}
	dest := s.TLSSettings.Dest
	if dest == "" && s.TLSSettings.Sni != "" {
		dest = s.TLSSettings.Sni + ":" + defaultOr(s.TLSSettings.ServerPort, "443")
	} else if dest != "" {
		dest = dest + ":" + defaultOr(s.TLSSettings.ServerPort, "443")
	}
	shortId := s.TLSSettings.ShortId
	var shortIds []string
	if shortId != "" {
		shortIds = []string{shortId}
	}
	serverNames := []string{s.TLSSettings.Sni}
	return &api.REALITYConfig{
		Dest:             dest,
		ProxyProtocolVer: s.TLSSettings.Xver,
		ServerNames:      serverNames,
		PrivateKey:       s.TLSSettings.PrivateKey,
		ShortIds:         shortIds,
	}
}

func defaultOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

var _ = net.ParseAddress // keep import parity with sibling clients
var _ = conf.NameServerConfig{}
