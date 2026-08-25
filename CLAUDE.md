# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

XrayR is a proxy server backend framework that bridges billing-panel APIs (Xboard, V2board, SSPanel, PMpanel, ProxyPanel, V2RaySocks, GoV2Panel, BunPanel) to an embedded [xray-core](https://github.com/XTLS/Xray-core) instance. It fetches node/user info from panels, runs inbounds for vmess/vless/trojan/shadowsocks/hysteria2, enforces speed/device/IP limits, reports traffic back, and manages TLS certs. One process can serve multiple panels/nodes simultaneously.

**xray-core is used unmodified from the official repo** (pinned commit in go.mod, no `replace` directive, no fork). The only "injection" point is the plugin mechanism: `panel.go` registers our own `app/mydispatcher` in place of the stock dispatcher. See "Upgrading xray-core" below for the maintenance SOP.

`origin code/` is local reference material only (upstream Xray-core, Xboard-Node, Xboard sources) — it must stay gitignored and never be committed.

## Commands

```bash
go build -o XrayR -trimpath -ldflags "-s -w -buildid="   # build (CGO_ENABLED=0 works everywhere)
go test ./...                                            # run all tests
go test ./api/sspanel/...                                # test one package
go test -run TestBuildTrojan ./service/controller/...    # run a single test
go vet ./...                                             # lint
```

Run: `./XrayR --config config.yml` (viper watches the file and hot-restarts the panel on change). Subcommands: `version`, `x25519` (generate REALITY keypair).

CI builds with `CGO_ENABLED=0` across many GOOS/GOARCH (see `.github/workflows/release.yml`); Dockerfile builds from `golang:1.26-alpine`.

## Architecture

Startup flow: `main.go` → `cmd.Execute()` (cobra) → viper unmarshals `config.yml` into `panel.Config` → `panel.Panel.Start()`.

### Core wiring

`panel/panel.go` builds an `xray-core` `core.Config` directly (not from JSON): log/dns/route configs are read from external JSON files if configured, plus **the custom `mydispatcher` is registered instead of the stock xray dispatcher**. This happens via blank imports of `cmd/distro/all` (`panel.go` and tests import it), which pulls in all xray-core proxies/transports and `_ "github.com/aprpure/XrayR/app/mydispatcher"`. The dispatcher's `init()` registers itself for `mydispatcher.Config`, so `core.New()` instantiates it as the routing.Dispatcher feature.

### Per-node flow

For each entry under `Nodes:` in config.yml, `Panel.Start()`:

1. Instantiates the matching `api.API` implementation (switch on `PanelType`; one subpackage per panel under `api/`). All clients implement the same interface (`api/api.go`): `GetNodeInfo`, `GetUserList`, `GetNodeRule`, `ReportNodeStatus`, `ReportNodeOnlineUsers`, `ReportUserTraffic`, `ReportIllegal`. Clients signal "nothing changed" via sentinel errors (`api.NodeNotModified`, `api.UserNotModified`, `api.RuleNotModified`) to skip rebuilds.
2. Creates a `controller.Controller` (`service/controller/controller.go`) wrapping the shared `core.Instance` and starts it as a `service.Service` (`Start`/`Close`).

The controller fetches node info, then builds and registers xray objects dynamically through feature managers: inbound/outbound handlers (`inboundbuilder.go` / `outboundbuilder.go`), protocol users (`userbuilder.go`), limiter, rules. Node identity/tag format: `{NodeType}_{ListenIP}_{Port}` — used as inbound tag, limiter key, counter scope. When nodeInfo changes, the old tag is removed and everything rebuilt under a new tag.

Periodic tasks (every `UpdatePeriodic` seconds):
- **nodeInfoMonitor** — re-fetch node + users; diff user lists (add/remove incrementally), rebuild inbound if node config changed, refresh rules.
- **userInfoMonitor** — read per-user traffic from xray stats counters (named `user>>>{email}>>>traffic>>>uplink|downlink`), report & reset counters; online-IP detection/reporting; auto speed-limiting of overspeed users.
- **certMonitor** — TLS cert issue/renewal via `common/mylego` (lego/acme); skipped when REALITY is enabled.

### mydispatcher (the custom xray dispatcher)

`app/mydispatcher` is a fork of xray's `app/dispatcher`. Its reason to exist: on every dispatch it consults two XrayR managers before routing:

- `Limiter` (`common/limiter`) — per-inbound state (keyed by node tag): per-user rate buckets (`golang.org/x/time/rate`), device limits (optionally Redis-backed global limits via gocache), online IP tracking, alive-IP list from v2board. Wraps link writers with `RateWriter` when a bucket applies.
- `RuleManager` (`common/rule`) — audit rules (regex from panel or local `rulelist` file); matches destination+email, records `DetectResult`s which get reported via `ReportIllegal`.

It also wires `SizeStatWriter` so per-user uplink/downlink counters populate the stats counters the controller reads.

### Config mapping

YAML keys come from `mapstructure` tags: top-level in `panel/config.go`, API settings in `api/apimodel.go` (`api.Config`), controller settings in `service/controller/config.go`. Defaults live in `panel/defaultConfig.go` / `service/controller/defaultConfig.go` and are merged with user config (mergo/diff). Example config: `release/config/config.yml.example`; example route/dns/custom in/out JSON files ship alongside it and in release zips.

### Pull/push intervals

Three periodic cadences resolved in `Controller.Start()` with priority: local `PullInterval`/`PushInterval` (ControllerConfig) > panel-provided `base_config` (exposed as `NodeInfo.PullInterval/PushInterval`) > deprecated `UpdatePeriodic` > 60s. Pull drives nodeInfoMonitor + userInfoMonitor + certMonitor(×60); push drives the separate pushMonitor. userInfoMonitor reads counters + auto-limit decisions and stashes them into `c.pendingTraffic`; pushMonitor takes the batch, reports, and resets xray counters only on success — on failure the batch is DISCARDED (counters keep accumulating, so the next cumulative reading contains everything; restoring stale snapshots would under-report). Shared state (`userList`, `nodeInfo`, `Tag`, `pendingTraffic`, `limitedUsers`, `warnedUsers`) is guarded by `trafficMu` because nodeInfoMonitor / userInfoMonitor / pushMonitor run concurrently.

## Upgrading xray-core

xray-core is a plain Go module dependency pinned to an official commit. Upgrade SOP:

```bash
# pick latest tag or master HEAD commit from https://github.com/XTLS/Xray-core
go get github.com/xtls/xray-core@<tag-or-commit>
go mod tidy
go build ./...   # fix breakages, see below
```

The touch surface is only 4 files (~1700 lines):
- `app/mydispatcher/default.go` — dispatcher internals change most often (stats counter signatures, session types, sniffer config)
- `cmd/distro/all/all.go` — upstream adds/removes proxy/transport packages → adjust blank imports
- `service/controller/inboundbuilder.go` — `infra/conf` struct fields (e.g. IVCheck removal, StringList pointer→value)
- `service/controller/userbuilder.go` — protocol enum constants (e.g. CipherType_NONE removed)

Then: `go vet ./...`, `go test ./api/xboard/ ./service/controller/ -count=1`, deploy to test server and verify each protocol connects. Commit the upgrade separately so go.mod/go.sum can be reverted alone. Don't chase every release — align every 1-2 months or on security advisories.

## Deployment (test server)

Server `47.131.129.0` (AWS Ubuntu 22.04): binary at `/usr/local/bin/XrayR`, config `/etc/XrayR/config.yml`, systemd unit `XrayR.service`. Nginx terminates TLS for `test.341100.xyz` (cert via acme.sh) and forwards gRPC `/trogun/Tun` → 127.0.0.1:11443, WS `/imemo` → 12443. Cross-compile with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o XrayR-linux ...`. SSH needs paramiko (password auth) or the installed pubkey.
