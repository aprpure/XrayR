package controller_test

import (
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/core"

	"github.com/aprpure/XrayR/api"
	"github.com/aprpure/XrayR/common/mylego"
	. "github.com/aprpure/XrayR/service/controller"
)

func TestBuildV2ray(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "V2ray",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "ws",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "test.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildTrojan(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Trojan",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		Host:              "trojan.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@gmail.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildSS(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Shadowsocks",
		NodeID:            1,
		Port:              1145,
		SpeedLimit:        0,
		AlterID:           2,
		TransportProtocol: "tcp",
		CypherMethod:      "aes-256-gcm",
		ServerKey:         "test_server_key",
		Host:              "test.test.tk",
		Path:              "v2ray",
		EnableTLS:         false,
	}
	DNSEnv := make(map[string]string)
	DNSEnv["ALICLOUD_ACCESS_KEY"] = "aaa"
	DNSEnv["ALICLOUD_SECRET_KEY"] = "bbb"
	certConfig := &mylego.CertConfig{
		CertMode:   "dns",
		CertDomain: "trojan.test.tk",
		Provider:   "alidns",
		Email:      "test@me.com",
		DNSEnv:     DNSEnv,
	}
	config := &Config{
		CertConfig: certConfig,
	}
	_, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Error(err)
	}
}

func TestBuildHysteria2(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Hysteria",
		NodeID:            1,
		Port:              443,
		TransportProtocol: "hysteria",
		HysteriaVersion:   2,
		UpMbps:            100,
		DownMbps:          500,
		Obfs:              "salamander",
		ObfsPassword:      "obfspass",
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "none",
		CertDomain: "test.test.tk",
	}
	config := &Config{
		CertConfig: certConfig,
	}
	inbound, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Fatal(err)
	}
	if inbound == nil {
		t.Fatal("inbound is nil")
	}
}

// receiverSettings decodes the serialized receiver config of a built inbound.
func receiverSettings(t *testing.T, in *core.InboundHandlerConfig) *proxyman.ReceiverConfig {
	t.Helper()
	instance, err := in.ReceiverSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	receiver, ok := instance.(*proxyman.ReceiverConfig)
	if !ok {
		t.Fatalf("ReceiverSettings is %T, want *proxyman.ReceiverConfig", instance)
	}
	return receiver
}

// trustedXFF returns the sockopt forwarding-header allowlist of a built
// inbound, or nil when no sockopt block was created.
func trustedXFF(t *testing.T, in *core.InboundHandlerConfig) []string {
	t.Helper()
	ss := receiverSettings(t, in).GetStreamSettings()
	if ss.GetSocketSettings() == nil {
		return nil
	}
	return ss.GetSocketSettings().GetTrustedXForwardedFor()
}

// TestBuildTrustedXForwardedFor verifies that TrustedXForwardedFor reaches the
// built stream settings, which is the only way xray-core will honour a reverse
// proxy's forwarding header instead of the real (loopback) peer address.
func TestBuildTrustedXForwardedFor(t *testing.T) {
	tests := []struct {
		name   string
		proto  string
		config *Config
		want   []string
	}{
		{
			name:   "unset leaves no allowlist",
			proto:  "grpc",
			config: &Config{},
			want:   nil,
		},
		{
			name:   "set on grpc",
			proto:  "grpc",
			config: &Config{TrustedXForwardedFor: []string{"X-Forwarded-For"}},
			want:   []string{"X-Forwarded-For"},
		},
		{
			name:   "set on websocket",
			proto:  "ws",
			config: &Config{TrustedXForwardedFor: []string{"X-Forwarded-For"}},
			want:   []string{"X-Forwarded-For"},
		},
		{
			name:   "set on tcp",
			proto:  "tcp",
			config: &Config{TrustedXForwardedFor: []string{"X-Forwarded-For"}},
			want:   []string{"X-Forwarded-For"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := &api.NodeInfo{
				NodeType:          "Trojan",
				NodeID:            1,
				Port:              11443,
				TransportProtocol: tc.proto,
				ServiceName:       "trogun",
			}
			in, err := InboundBuilder(tc.config, nodeInfo, "test_tag")
			if err != nil {
				t.Fatal(err)
			}
			got := trustedXFF(t, in)
			if len(got) != len(tc.want) {
				t.Fatalf("TrustedXForwardedFor = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("TrustedXForwardedFor = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestBuildTrustedXForwardedForCopiesConfig guards the defensive copy: the
// config is reused across inbound rebuilds, so a later mutation of the slice
// must not retroactively change an already-built socket config.
func TestBuildTrustedXForwardedForCopiesConfig(t *testing.T) {
	headers := []string{"X-Forwarded-For"}
	config := &Config{TrustedXForwardedFor: headers}
	nodeInfo := &api.NodeInfo{
		NodeType:          "Trojan",
		NodeID:            1,
		Port:              11443,
		TransportProtocol: "grpc",
		ServiceName:       "trogun",
	}

	in, err := InboundBuilder(config, nodeInfo, "test_tag")
	if err != nil {
		t.Fatal(err)
	}
	headers[0] = "X-Evil"

	got := trustedXFF(t, in)
	if len(got) != 1 || got[0] != "X-Forwarded-For" {
		t.Fatalf("built inbound aliased the config slice: %v", got)
	}
}

func TestBuildHysteria1Rejected(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:          "Hysteria",
		NodeID:            1,
		Port:              443,
		TransportProtocol: "hysteria",
		HysteriaVersion:   1,
		EnableTLS:         true,
	}
	config := &Config{CertConfig: &mylego.CertConfig{CertMode: "none"}}
	if _, err := InboundBuilder(config, nodeInfo, "test_tag"); err == nil {
		t.Error("expected error for hysteria v1, got nil")
	}
}
