package gov2panel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"
	"github.com/gogf/gf/v2/util/gconv"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/aprpure/XrayR/api"
)

// APIClient create an api client to the panel.
type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	VlessFlow     string
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
	resp          atomic.Value
	eTags         map[string]string
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
	// Retry only idempotent GETs; never re-send POSTs (traffic reports are
	// not idempotent - a lost response followed by a retry double-counts).
	client.AddRetryCondition(func(r *resty.Response, err error) bool {
		return err != nil && r.Request.Method != "POST"
	})
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)
	// Create Key for each requests
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": strings.ToLower(apiConfig.NodeType),
		"token":     apiConfig.Key,
	})
	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		VlessFlow:     apiConfig.VlessFlow,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
		eTags:         make(map[string]string),
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file, one regexp per line.
// Bad lines are logged and skipped; a single invalid rule must not kill the
// process (regexp.MustCompile would panic).
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)

	if path == "" {
		return LocalRuleList
	}

	file, err := os.Open(path)
	if err != nil {
		log.Printf("Error when opening file: %s", err)
		return LocalRuleList
	}
	defer file.Close()

	fileScanner := bufio.NewScanner(file)
	for fileScanner.Scan() {
		pattern, err := regexp.Compile(fileScanner.Text())
		if err != nil {
			log.Printf("Skipping invalid rule %q: %s", fileScanner.Text(), err)
			continue
		}
		LocalRuleList = append(LocalRuleList, api.DetectRule{
			ID:      -1,
			Pattern: pattern,
		})
	}
	if err := fileScanner.Err(); err != nil {
		log.Printf("Error while reading file: %s", err)
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

// parseResponse validates the transport error and status code. The body is
// returned untouched so callers can json.Unmarshal it straight into their
// structs (no intermediate simplejson parse/re-encode round trip).
func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*resty.Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.assembleURL(path), err)
	}

	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s, %v", c.assembleURL(path), res.String(), err)
	}

	return res, nil
}

// GetNodeInfo will pull NodeInfo Config from panel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	server := new(serverConfig)
	path := "/api/server/config"

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["node"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrNodeNotModified
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["node"] {
		c.eTags["node"] = res.Header().Get("Etag")
	}

	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(res.Body(), server); err != nil {
		return nil, fmt.Errorf("parse node config failed: %s, \nError: %v", res.String(), err)
	}

	if gconv.Uint32(server.Port) == 0 {
		return nil, errors.New("server port must > 0")
	}

	c.resp.Store(server)

	switch c.NodeType {
	case "V2ray", "Vmess", "Vless":
		nodeInfo, err = c.parseV2rayNodeResponse(server)
	case "Trojan":
		nodeInfo, err = c.parseTrojanNodeResponse(server)
	case "Shadowsocks":
		nodeInfo, err = c.parseSSNodeResponse(server)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	if err != nil {
		return nil, fmt.Errorf("parse node info failed: %s, \nError: %v", res.String(), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form panel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var users []*user
	path := "/api/server/user"

	switch c.NodeType {
	case "V2ray", "Trojan", "Shadowsocks", "Vmess", "Vless":
		break
	default:
		return nil, fmt.Errorf("unsupported node type: %s", c.NodeType)
	}

	res, err := c.client.R().
		SetHeader("If-None-Match", c.eTags["users"]).
		ForceContentType("application/json").
		Get(path)

	// Etag identifier for a specific version of a resource. StatusCode = 304 means no changed
	if res.StatusCode() == 304 {
		return nil, api.ErrUserNotModified
	}
	// update etag
	if res.Header().Get("Etag") != "" && res.Header().Get("Etag") != c.eTags["users"] {
		c.eTags["users"] = res.Header().Get("Etag")
	}

	res, err = c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	usersResp := struct {
		Users []*user `json:"users"`
	}{}
	if err := json.Unmarshal(res.Body(), &usersResp); err != nil {
		return nil, fmt.Errorf("parse user list failed: %s, \nError: %v", res.String(), err)
	}
	users = usersResp.Users
	if len(users) == 0 {
		return nil, errors.New("users is null")
	}

	userList := make([]api.UserInfo, len(users))
	for i := 0; i < len(users); i++ {
		u := api.UserInfo{
			UID:  users[i].Id,
			UUID: users[i].Uuid,
		}

		// Support 1.7.1 speed limit
		if c.SpeedLimit > 0 {
			u.SpeedLimit = uint64(c.SpeedLimit * 1000000 / 8)
		} else {
			u.SpeedLimit = uint64(users[i].SpeedLimit * 1000000 / 8)
		}

		u.DeviceLimit = c.DeviceLimit // todo waiting v2board send configuration
		u.Email = u.UUID + "@gov2panel.user"
		if c.NodeType == "Shadowsocks" {
			u.Passwd = u.UUID
		}
		userList[i] = u
	}

	return &userList, nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	path := "/api/server/push"

	res, err := c.client.R().SetBody(userTraffic).ForceContentType("application/json").Post(path)
	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule implements the API interface
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	routes := c.resp.Load().(*serverConfig).Routes

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

// ReportNodeStatus implements the API interface
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	return nil
}

// ReportNodeOnlineUsers implements the API interface
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {
	return nil
}

// ReportIllegal implements the API interface
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	return nil
}

// parseTrojanNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseTrojanNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	// Create GeneralNodeInfo
	nodeInfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              gconv.Uint32(s.Port),
		TransportProtocol: "tcp",
		EnableTLS:         true,
		Host:              s.Host,
		ServiceName:       s.Sni,
		NameServerConfig:  s.parseDNSConfig(),
	}
	return nodeInfo, nil
}

// parseSSNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseSSNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var header json.RawMessage

	if s.Obfs == "http" {
		path := "/"
		if p := s.ObfsSettings.Path; p != "" {
			if strings.HasPrefix(p, "/") {
				path = p
			} else {
				path += p
			}
		}
		header = json.RawMessage(`{"type":"http","request":{"path":` + strconv.Quote(path) + `}}`)
	}
	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              gconv.Uint32(s.Port),
		TransportProtocol: "tcp",
		CypherMethod:      s.Encryption,
		ServerKey:         s.ServerKey, // shadowsocks2022 share key
		NameServerConfig:  s.parseDNSConfig(),
		Header:            header,
	}, nil
}

// parseV2rayNodeResponse parse the response for the given nodeInfo format
func (c *APIClient) parseV2rayNodeResponse(s *serverConfig) (*api.NodeInfo, error) {
	var (
		header    json.RawMessage
		enableTLS bool
	)

	switch s.Net {
	case "tcp":
		if s.Header != nil {
			if httpHeader, err := s.Header.MarshalJSON(); err != nil {
				return nil, err
			} else {
				header = httpHeader
			}
		}
	}

	if s.TLS == "tls" {
		enableTLS = true
	}

	// Create GeneralNodeInfo
	return &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              gconv.Uint32(s.Port),
		AlterID:           0,
		TransportProtocol: s.Net,
		EnableTLS:         enableTLS,
		Path:              s.Path,
		Host:              s.Host,
		EnableVless:       c.EnableVless,
		VlessFlow:         c.VlessFlow,
		ServiceName:       s.Sni,
		Header:            header,
		NameServerConfig:  s.parseDNSConfig(),
	}, nil
}

func (s *serverConfig) parseDNSConfig() (nameServerList []*conf.NameServerConfig) {
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
