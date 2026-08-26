package controller_test

import (
	"runtime"
	"testing"

	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	"github.com/aprpure/XrayR/api"
	"github.com/aprpure/XrayR/api/sspanel"
	"github.com/aprpure/XrayR/app/mydispatcher"
	_ "github.com/aprpure/XrayR/cmd/distro/all"
	"github.com/aprpure/XrayR/common/mylego"
	. "github.com/aprpure/XrayR/service/controller"
)

// TestController spins up a core instance with mydispatcher and starts a
// controller against an unreachable panel host. Controller.Start returns the
// panel fetch error — that is the behavior under test (no panic, no hang).
func TestController(t *testing.T) {
	serverConfig := &conf.Config{
		Stats:     &conf.StatsConfig{},
		LogConfig: &conf.LogConfig{LogLevel: "debug"},
	}
	policyConfig := &conf.PolicyConfig{}
	policyConfig.Levels = map[uint32]*conf.Policy{0: {
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}}
	serverConfig.Policy = policyConfig
	config, err := serverConfig.Build()
	if err != nil {
		t.Fatalf("build server config: %s", err)
	}

	// conf.Config.Build() injects the stock dispatcher.Config as the first app;
	// replace it with XrayR's mydispatcher (panel.go does the same when building
	// the production config).
	config.App[0] = serial.ToTypedMessage(&mydispatcher.Config{})

	server, err := core.New(config)
	if err != nil {
		t.Fatalf("failed to create instance: %s", err)
	}
	defer server.Close()
	if err := server.Start(); err != nil {
		t.Fatalf("failed to start instance: %s", err)
	}
	certConfig := &mylego.CertConfig{
		CertMode:   "http",
		CertDomain: "test.ss.tk",
		Provider:   "alidns",
		Email:      "ss@ss.com",
	}
	controllerConfig := &Config{
		UpdatePeriodic: 5,
		CertConfig:     certConfig,
	}
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:667",
		Key:      "123",
		NodeID:   41,
		NodeType: "V2ray",
	}
	apiClient := sspanel.New(apiConfig)
	c := New(server, apiClient, controllerConfig, "SSPanel")
	// The panel at 127.0.0.1:667 does not exist; Start must fail cleanly.
	if err := c.Start(); err == nil {
		t.Error("expected Start to fail with unreachable panel, got nil")
	}
	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
}
