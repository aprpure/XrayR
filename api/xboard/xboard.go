package xboard

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/go-resty/resty/v2"

	"github.com/aprpure/XrayR/api"
)

// APIClient is an api client to the Xboard panel (V2 API with automatic
// fallback to the legacy V1 UniProxy API when the panel does not provide V2).
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
	eTags         eTagStore // guarded map; read/written by concurrent monitor goroutines

	useV1 atomic.Bool // set once a V2 endpoint returns 404; all subsequent requests use V1 paths
}

// eTagStore is a mutex-guarded string map for ETag caching.
type eTagStore struct {
	mu   sync.RWMutex
	data map[string]string
}

func newETagStore() eTagStore {
	return eTagStore{data: make(map[string]string)}
}

func (s *eTagStore) get(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data[key]
}

func (s *eTagStore) set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
}

// New create an api instance
func New(apiConfig *api.Config) *APIClient {
	client := resty.New()
	client.SetRetryCount(3)
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

	// Auth params for every request (token + node_id + node_type)
	client.SetQueryParams(map[string]string{
		"node_id":   strconv.Itoa(apiConfig.NodeID),
		"node_type": strings.ToLower(nodeTypeForRequests(apiConfig.NodeType, apiConfig.EnableVless)),
		"token":     apiConfig.Key,
	})

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
		eTags:         newETagStore(),
	}
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {
	LocalRuleList = make([]api.DetectRule, 0)

	if path != "" {
		// open the file
		file, err := os.Open(path)
		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}
		defer file.Close()
		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if fileScanner.Err() != nil {
			log.Fatalf("Error while reading file: %s", fileScanner.Err())
			return
		}
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

// configPath returns the node config path for the currently selected API version.
func (c *APIClient) configPath() string {
	if c.useV1.Load() {
		return "/api/v1/server/UniProxy/config"
	}
	return "/api/v2/server/config"
}

// userPath returns the user list path for the currently selected API version.
func (c *APIClient) userPath() string {
	if c.useV1.Load() {
		return "/api/v1/server/UniProxy/user"
	}
	return "/api/v2/server/user"
}

// nodeTypeForRequests maps local NodeType to the panel's server type.
// Mirrors the NewV2board client: NodeType=V2ray selects vless only when the
// local EnableVless switch is on; otherwise it stays "V2ray", which the panel
// normalizes to vmess (Server.php TYPE_ALIASES).
func nodeTypeForRequests(nodeType string, enableVless bool) string {
	switch nodeType {
	case "V2ray":
		if enableVless {
			return "vless"
		}
		return "V2ray"
	case "Hysteria", "Hysteria2":
		return "hysteria"
	default:
		return nodeType
	}
}

// parseResponseNoAuth performs the request handling common to GET endpoints and
// detects V2 endpoints that are not available on the panel (404), switching the
// client permanently to V1 paths. Returns the response or an error.
func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*resty.Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %v", c.APIHost+path, err)
	}

	// V2 endpoint missing on older panels: fall back to V1 UniProxy permanently.
	if !c.useV1.Load() && !strings.HasPrefix(path, "/api/v1/") && res.StatusCode() == 404 {
		log.Printf("Panel does not support V2 API (%s returned 404), falling back to V1 UniProxy", path)
		c.useV1.Store(true)
		return res, nil
	}

	if res.StatusCode() > 399 {
		return nil, fmt.Errorf("request %s failed: %s, %v", c.APIHost+path, res.String(), err)
	}

	return res, nil
}
