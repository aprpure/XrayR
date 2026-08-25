package xboard_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wyx2685/XrayR/api"
	"github.com/wyx2685/XrayR/api/xboard"
)

// mockPanel emulates the Xboard panel endpoints used by the client.
type mockPanel struct {
	v2Enabled bool

	configV2Calls int
	configV1Calls int
	userV2Calls   int
	userV1Calls   int
	pushV1Calls   int
	reportV2Calls int

	configBody string
	userBody   string
}

func (m *mockPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case path == "/api/v2/server/config":
		m.configV2Calls++
		if !m.v2Enabled {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("token") == "" || r.URL.Query().Get("node_id") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if match := r.Header.Get("If-None-Match"); match != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", etagOf(m.configBody)))
		w.Write([]byte(m.configBody))
	case path == "/api/v1/server/UniProxy/config":
		m.configV1Calls++
		if match := r.Header.Get("If-None-Match"); match != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", etagOf(m.configBody)))
		w.Write([]byte(m.configBody))
	case path == "/api/v2/server/user":
		m.userV2Calls++
		if !m.v2Enabled {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(m.userBody))
	case path == "/api/v1/server/UniProxy/user":
		m.userV1Calls++
		w.Write([]byte(m.userBody))
	case path == "/api/v1/server/UniProxy/push":
		m.pushV1Calls++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": true}`))
	case path == "/api/v2/server/report":
		m.reportV2Calls++
		if !m.v2Enabled {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": true}`))
	default:
		http.NotFound(w, r)
	}
}

func etagOf(s string) string {
	// Deterministic fake etag; the client only compares equality.
	return fmt.Sprintf("%x", len(s))
}

func newTestClient(t *testing.T, server *httptest.Server) api.API {
	t.Helper()
	client := xboard.New(&api.Config{
		APIHost:     server.URL,
		Key:         "test-token",
		NodeID:      41,
		NodeType:    "V2ray",
		EnableVless: true, // mock panel serves a vless node
	})
	return client
}

const vlessConfigJSON = `{
  "protocol": "vless",
  "listen_ip": "0.0.0.0",
  "server_port": 443,
  "network": "ws",
  "networkSettings": {"path": "/ray", "headers": {"Host": "example.com"}},
  "tls": 2,
  "flow": "xtls-rprx-vision",
  "tls_settings": {
    "server_name": "example.com",
    "dest": "example.com",
    "server_port": "8443",
    "private_key": "kMf9EbrQCLv0PsORoNcftWUdD5S1ghB4H8UIHweByUc",
    "short_id": "0123ab",
    "xver": "1"
  },
  "base_config": {"push_interval": 300, "pull_interval": 180},
  "routes": [
    {"id": 1, "match": ["(api|www)\\.example\\.com"], "action": "block"},
    {"id": 2, "match": ["google.com"], "action": "dns", "action_value": "8.8.8.8"}
  ]
}`

const usersJSON = `{"users": [
  {"id": 101, "uuid": "uuid-a", "speed_limit": 100, "device_limit": 3},
  {"id": 102, "uuid": "uuid-b", "speed_limit": 0, "device_limit": 0}
]}`

func TestGetNodeInfoV2(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if panel.configV2Calls != 1 || panel.configV1Calls != 0 {
		t.Errorf("expected V2 config call only, got v2=%d v1=%d", panel.configV2Calls, panel.configV1Calls)
	}
	if nodeInfo.Port != 443 {
		t.Errorf("Port = %d, want 443", nodeInfo.Port)
	}
	if nodeInfo.TransportProtocol != "ws" {
		t.Errorf("TransportProtocol = %s, want ws", nodeInfo.TransportProtocol)
	}
	if nodeInfo.Path != "/ray" {
		t.Errorf("Path = %s, want /ray", nodeInfo.Path)
	}
	if nodeInfo.Host != "example.com" {
		t.Errorf("Host = %s, want example.com", nodeInfo.Host)
	}
	if !nodeInfo.EnableTLS || !nodeInfo.EnableREALITY {
		t.Errorf("EnableTLS=%v EnableREALITY=%v, want both true", nodeInfo.EnableTLS, nodeInfo.EnableREALITY)
	}
	if nodeInfo.REALITYConfig == nil || nodeInfo.REALITYConfig.PrivateKey != "kMf9EbrQCLv0PsORoNcftWUdD5S1ghB4H8UIHweByUc" {
		t.Errorf("REALITYConfig = %+v, want private key set", nodeInfo.REALITYConfig)
	}
	if len(nodeInfo.REALITYConfig.ShortIds) != 1 || nodeInfo.REALITYConfig.ShortIds[0] != "0123ab" {
		t.Errorf("ShortIds = %v, want [0123ab]", nodeInfo.REALITYConfig.ShortIds)
	}
	if !nodeInfo.EnableVless {
		t.Error("EnableVless should be true for V2ray NodeType on vless protocol node")
	}
	if nodeInfo.VlessFlow != "xtls-rprx-vision" {
		t.Errorf("VlessFlow = %s", nodeInfo.VlessFlow)
	}
}

func TestGetNodeInfoFallbackToV1(t *testing.T) {
	panel := &mockPanel{v2Enabled: false, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if panel.configV2Calls != 1 {
		t.Errorf("expected exactly one V2 attempt, got %d", panel.configV2Calls)
	}
	if panel.configV1Calls != 1 {
		t.Errorf("expected fallback to V1 once, got %d", panel.configV1Calls)
	}
	if nodeInfo.Port != 443 {
		t.Errorf("Port = %d, want 443", nodeInfo.Port)
	}

	// After the config endpoint already fell back, the user request must go
	// straight to V1 (the fallback flag is client-wide, not per-endpoint).
	if _, err := client.GetUserList(); err != nil {
		t.Fatal(err)
	}
	if panel.userV2Calls != 0 || panel.userV1Calls != 1 {
		t.Errorf("expected V1 user directly after client-wide fallback, got v2=%d v1=%d",
			panel.userV2Calls, panel.userV1Calls)
	}

	// Config polling after fallback must hit V1 directly (no more V2 attempts).
	v2Before := panel.configV2Calls
	if _, err := client.GetNodeInfo(); err == nil || err.Error() != api.NodeNotModified {
		// mock returns fresh body; either outcome is fine as long as no V2 call was made
		_ = err
	}
	if panel.configV2Calls != v2Before {
		t.Errorf("expected no additional V2 config calls after fallback, went %d -> %d", v2Before, panel.configV2Calls)
	}
}

func TestGetUserList(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	users, err := client.GetUserList()
	if err != nil {
		t.Fatal(err)
	}
	if len(*users) != 2 {
		t.Fatalf("got %d users, want 2", len(*users))
	}
	u := (*users)[0]
	if u.UID != 101 || u.UUID != "uuid-a" {
		t.Errorf("user = %+v", u)
	}
	if u.SpeedLimit != 12500000 { // 100 Mbps -> Bps
		t.Errorf("SpeedLimit = %d, want 12500000", u.SpeedLimit)
	}
	if u.DeviceLimit != 3 {
		t.Errorf("DeviceLimit = %d, want 3", u.DeviceLimit)
	}
	if !strings.Contains(u.Email, "@xboard.user") {
		t.Errorf("Email = %s, want @xboard.user suffix", u.Email)
	}
}

func TestETagNotModified(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	_, err := client.GetNodeInfo()
	if err == nil || err.Error() != api.NodeNotModified {
		t.Errorf("second GetNodeInfo err = %v, want NodeNotModified", err)
	}

	if _, err := client.GetUserList(); err != nil {
		t.Fatal(err)
	}
	// Note: mock always returns fresh body without honoring ETag for users;
	// ETag handling for users is covered by the config test above.
}

func TestReportUserTraffic(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	traffic := []api.UserTraffic{{UID: 101, Upload: 100, Download: 200}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
	if panel.reportV2Calls != 1 {
		t.Errorf("expected 1 V2 report call, got %d", panel.reportV2Calls)
	}
}

func TestReportUserTrafficV1(t *testing.T) {
	panel := &mockPanel{v2Enabled: false, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	traffic := []api.UserTraffic{{UID: 101, Upload: 100, Download: 200}}
	if err := client.ReportUserTraffic(&traffic); err != nil {
		t.Fatal(err)
	}
	if panel.pushV1Calls != 1 {
		t.Errorf("expected 1 V1 push call, got %d", panel.pushV1Calls)
	}
}

func TestGetNodeRule(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	if _, err := client.GetNodeInfo(); err != nil {
		t.Fatal(err)
	}
	rules, err := client.GetNodeRule()
	if err != nil {
		t.Fatal(err)
	}
	if len(*rules) != 1 {
		t.Fatalf("got %d rules, want 1 (block only)", len(*rules))
	}
	if (*rules)[0].Pattern.String() != "(api|www)\\.example\\.com" {
		t.Errorf("pattern = %s", (*rules)[0].Pattern.String())
	}
}

func TestEnableVlessLocalSwitch(t *testing.T) {
	// NodeType=V2ray + EnableVless=true -> panel vless node accepted, vmess rejected
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := xboard.New(&api.Config{
		APIHost:     server.URL,
		Key:         "test-token",
		NodeID:      41,
		NodeType:    "V2ray",
		EnableVless: true,
	})
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !nodeInfo.EnableVless {
		t.Error("EnableVless should be true when local switch is on and panel node is vless")
	}

	// Switch off but panel serves a vless node -> mismatch error
	panel2 := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server2 := httptest.NewServer(panel2)
	defer server2.Close()

	client2 := xboard.New(&api.Config{
		APIHost:     server2.URL,
		Key:         "test-token",
		NodeID:      41,
		NodeType:    "V2ray",
		EnableVless: false,
	})
	if _, err := client2.GetNodeInfo(); err == nil {
		t.Error("expected error: local switch off but panel serves vless node")
	}

	// Switch off + panel serves a vmess node -> accepted as vmess
	vmessConfig := strings.Replace(vlessConfigJSON, `"protocol": "vless"`, `"protocol": "vmess"`, 1)
	panel3 := &mockPanel{v2Enabled: true, configBody: vmessConfig, userBody: usersJSON}
	server3 := httptest.NewServer(panel3)
	defer server3.Close()

	client3 := xboard.New(&api.Config{
		APIHost:     server3.URL,
		Key:         "test-token",
		NodeID:      41,
		NodeType:    "V2ray",
		EnableVless: false,
	})
	nodeInfo3, err := client3.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if nodeInfo3.EnableVless {
		t.Error("EnableVless should be false when local switch is off")
	}

	// Switch on + panel serves a vmess node -> mismatch error
	panel4 := &mockPanel{v2Enabled: true, configBody: vmessConfig, userBody: usersJSON}
	server4 := httptest.NewServer(panel4)
	defer server4.Close()

	client4 := xboard.New(&api.Config{
		APIHost:     server4.URL,
		Key:         "test-token",
		NodeID:      41,
		NodeType:    "V2ray",
		EnableVless: true,
	})
	if _, err := client4.GetNodeInfo(); err == nil {
		t.Error("expected error: local switch on but panel serves vmess node")
	}
}


func TestBaseConfigIntervals(t *testing.T) {
	panel := &mockPanel{v2Enabled: true, configBody: vlessConfigJSON, userBody: usersJSON}
	server := httptest.NewServer(panel)
	defer server.Close()

	client := newTestClient(t, server)

	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Fatal(err)
	}
	if nodeInfo.PushInterval != 300 {
		t.Errorf("PushInterval = %d, want 300 (panel base_config)", nodeInfo.PushInterval)
	}
	if nodeInfo.PullInterval != 180 {
		t.Errorf("PullInterval = %d, want 180 (panel base_config)", nodeInfo.PullInterval)
	}
}
