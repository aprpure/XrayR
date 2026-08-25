package panel

import "github.com/wyx2685/XrayR/service/controller"

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{
		Level:      "none",
		AccessPath: "",
		ErrorPath:  "",
	}
}

func getDefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		Handshake:    4,
		ConnIdle:     30,
		UplinkOnly:   2,
		DownlinkOnly: 4,
		BufferSize:   64,
	}
}

func getDefaultControllerConfig() *controller.Config {
	return &controller.Config{
		ListenIP: "0.0.0.0",
		SendIP:   "0.0.0.0",
		// UpdatePeriodic intentionally defaults to 0 here: when neither
		// PullInterval nor PushInterval is configured locally, the panel-provided
		// base_config intervals take effect (final fallback 60s lives in the controller).
		DNSType: "AsIs",
	}
}
