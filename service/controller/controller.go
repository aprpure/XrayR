package controller

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"

	"github.com/aprpure/XrayR/api"
	"github.com/aprpure/XrayR/api/newV2board"
	"github.com/aprpure/XrayR/app/mydispatcher"
	"github.com/aprpure/XrayR/common/mylego"
	"github.com/aprpure/XrayR/common/serverstatus"
)

type LimitInfo struct {
	end               int64
	currentSpeedLimit int
	originSpeedLimit  uint64
}

type Controller struct {
	server       *core.Instance
	config       *Config
	clientInfo   api.ClientInfo
	apiClient    api.API
	nodeInfo     *api.NodeInfo
	Tag          string
	userList     *[]api.UserInfo
	tasks        []periodicTask
	limitedUsers map[api.UserInfo]LimitInfo
	warnedUsers  map[api.UserInfo]int
	panelType    string
	ibm          inbound.Manager
	obm          outbound.Manager
	stm          stats.Manager
	dispatcher   *mydispatcher.DefaultDispatcher
	startAt      time.Time
	logger       *log.Entry

	// trafficMu guards pendingTraffic, limitedUsers and warnedUsers, which are
	// written by the pull-side monitor and read/cleared by the push-side monitor.
	trafficMu      sync.Mutex
	pendingTraffic *pendingTraffic
}

// pendingTraffic carries per-user counters read by the pull side to the push
// side, which reports them and (on success) resets the underlying xray counters.
type pendingTraffic struct {
	userTraffic   []api.UserTraffic
	upCounters    []stats.Counter
	downCounters  []stats.Counter
}

type periodicTask struct {
	tag string
	*task.Periodic
}

// New return a Controller service with default parameters.
func New(server *core.Instance, api api.API, config *Config, panelType string) *Controller {
	logger := log.NewEntry(log.StandardLogger()).WithFields(log.Fields{
		"Host": api.Describe().APIHost,
		"Type": api.Describe().NodeType,
		"ID":   api.Describe().NodeID,
	})
	controller := &Controller{
		server:     server,
		config:     config,
		apiClient:  api,
		panelType:  panelType,
		ibm:        server.GetFeature(inbound.ManagerType()).(inbound.Manager),
		obm:        server.GetFeature(outbound.ManagerType()).(outbound.Manager),
		stm:        server.GetFeature(stats.ManagerType()).(stats.Manager),
		dispatcher: server.GetFeature(routing.DispatcherType()).(*mydispatcher.DefaultDispatcher),
		startAt:    time.Now(),
		logger:     logger,
	}

	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	c.clientInfo = c.apiClient.Describe()
	// First fetch Node Info
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		return err
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}
	c.nodeInfo = newNodeInfo
	c.Tag = c.buildNodeTag()
	// No lock needed here: periodic tasks have not started yet.

	// Add new tag
	err = c.addNewTag(newNodeInfo)
	if err != nil {
		c.logger.Panic(err)
		return err
	}
	// Update user
	userInfo, err := c.apiClient.GetUserList()
	if err != nil {
		return err
	}

	// sync controller userList
	c.userList = userInfo

	err = c.addNewUser(userInfo, newNodeInfo)
	if err != nil {
		return err
	}

	// Add Limiter
	if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, userInfo, c.config.GlobalDeviceLimitConfig); err != nil {
		c.logger.Print(err)
	}

	// Update alive user list
	if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
		if err := c.dispatcher.Limiter.SetAliveList(c.Tag, v2b.AliveMap.Alive); err != nil {
			c.logger.Print(err)
		}
	}

	// Add Rule Manager
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			c.logger.Printf("Get rule list filed: %s", err)
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	// Init AutoSpeedLimitConfig
	if c.config.AutoSpeedLimitConfig == nil {
		c.config.AutoSpeedLimitConfig = &AutoSpeedLimitConfig{0, 0, 0, 0}
	}
	if c.config.AutoSpeedLimitConfig.Limit > 0 {
		c.limitedUsers = make(map[api.UserInfo]LimitInfo)
		c.warnedUsers = make(map[api.UserInfo]int)
	}

	// Resolve pull/push intervals.
	// Priority: local explicit config > panel-provided base_config > legacy UpdatePeriodic > 60s.
	pullInterval := firstNonZero(c.config.PullInterval, c.nodeInfo.PullInterval, c.config.UpdatePeriodic, defaultUpdatePeriodic)
	pushInterval := firstNonZero(c.config.PushInterval, c.nodeInfo.PushInterval, c.config.UpdatePeriodic, defaultUpdatePeriodic)
	c.logger.Printf("Pull interval: %ds, Push interval: %ds", pullInterval, pushInterval)

	// Add periodic tasks
	c.tasks = append(c.tasks,
		periodicTask{
			tag: "node monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(pullInterval) * time.Second,
				Execute:  c.nodeInfoMonitor,
			}},
		periodicTask{
			tag: "user monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(pullInterval) * time.Second,
				Execute:  c.userInfoMonitor,
			}},
		periodicTask{
			tag: "traffic report",
			Periodic: &task.Periodic{
				Interval: time.Duration(pushInterval) * time.Second,
				Execute:  c.pushMonitor,
			}},
	)

	// Check cert service in need
	if c.nodeInfo.EnableTLS && !c.config.EnableREALITY {
		c.tasks = append(c.tasks, periodicTask{
			tag: "cert monitor",
			Periodic: &task.Periodic{
				Interval: time.Duration(pullInterval) * time.Second * 60,
				Execute:  c.certMonitor,
			}})
	}

	// Start periodic tasks
	for i := range c.tasks {
		c.logger.Printf("Start %s periodic task", c.tasks[i].tag)
		go c.tasks[i].Start()
	}

	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	for i := range c.tasks {
		if c.tasks[i].Periodic != nil {
			if err := c.tasks[i].Periodic.Close(); err != nil {
				c.logger.Panicf("%s periodic task close failed: %s", c.tasks[i].tag, err)
			}
		}
	}

	return nil
}

func (c *Controller) nodeInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(firstNonZero(c.config.PullInterval, defaultUpdatePeriodic))*time.Second {
		return nil
	}

	// First fetch Node Info
	var nodeInfoChanged = true
	newNodeInfo, err := c.apiClient.GetNodeInfo()
	if err != nil {
		if err.Error() == api.NodeNotModified {
			nodeInfoChanged = false
			newNodeInfo = c.nodeInfo
		} else {
			c.logger.Print(err)
			return nil
		}
	}
	if newNodeInfo.Port == 0 {
		return errors.New("server port must > 0")
	}

	// Update User
	var usersChanged = true
	newUserInfo, err := c.apiClient.GetUserList()

	// Update alive user list
	if v2b, ok := c.apiClient.(*newV2board.APIClient); ok {
		if err := c.dispatcher.Limiter.SetAliveList(c.Tag, v2b.AliveMap.Alive); err != nil {
			c.logger.Print(err)
		}
	}
	if err != nil {
		if err.Error() == api.UserNotModified {
			usersChanged = false
			newUserInfo = c.userList
		} else {
			c.logger.Print(err)
			return nil
		}
	}

	// If nodeInfo changed
	if nodeInfoChanged {
		if !reflect.DeepEqual(c.nodeInfo, newNodeInfo) {
			// Remove old tag
			oldTag := c.Tag
			err := c.removeOldTag(oldTag)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			// Drop limiter and rule state registered under the old tag.
			if err = c.DeleteInboundLimiter(oldTag); err != nil {
				c.logger.Print(err)
			}
			c.dispatcher.RuleManager.RemoveInbound(oldTag)
			if c.nodeInfo.NodeType == "Shadowsocks-Plugin" {
				err = c.removeOldTag(fmt.Sprintf("dokodemo-door_%s+1", c.Tag))
			}
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			// Add new tag
			c.trafficMu.Lock()
			c.nodeInfo = newNodeInfo
			c.Tag = c.buildNodeTag()
			c.trafficMu.Unlock()
			err = c.addNewTag(newNodeInfo)
			if err != nil {
				c.logger.Print(err)
				return nil
			}
			nodeInfoChanged = true
		} else {
			nodeInfoChanged = false
		}
	}

	// Check Rule
	if !c.config.DisableGetRule {
		if ruleList, err := c.apiClient.GetNodeRule(); err != nil {
			if err.Error() != api.RuleNotModified {
				c.logger.Printf("Get rule list filed: %s", err)
			}
		} else if len(*ruleList) > 0 {
			if err := c.UpdateRule(c.Tag, *ruleList); err != nil {
				c.logger.Print(err)
			}
		}
	}

	if nodeInfoChanged {
		err = c.addNewUser(newUserInfo, newNodeInfo)
		if err != nil {
			c.logger.Print(err)
			return nil
		}

		// Add Limiter
		if err := c.AddInboundLimiter(c.Tag, newNodeInfo.SpeedLimit, newUserInfo, c.config.GlobalDeviceLimitConfig); err != nil {
			c.logger.Print(err)
			return nil
		}

	} else {
		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = compareUserList(c.userList, newUserInfo)
			if len(deleted) > 0 {
				deletedEmail := make([]string, len(deleted))
				for i, u := range deleted {
					deletedEmail[i] = fmt.Sprintf("%s|%s|%d", c.Tag, u.Email, u.UID)
				}
				err := c.removeUsers(deletedEmail, c.Tag)
				if err != nil {
					c.logger.Print(err)
				}
			}
			if len(added) > 0 {
				err = c.addNewUser(&added, c.nodeInfo)
				if err != nil {
					c.logger.Print(err)
				}
				// Update Limiter
				if err := c.UpdateInboundLimiter(c.Tag, &added); err != nil {
					c.logger.Print(err)
				}
			}
		}
		c.logger.Printf("%d user deleted, %d user added", len(deleted), len(added))
	}
	c.trafficMu.Lock()
	c.userList = newUserInfo
	c.trafficMu.Unlock()
	return nil
}

func (c *Controller) removeOldTag(oldTag string) (err error) {
	err = c.removeInbound(oldTag)
	if err != nil {
		return err
	}
	err = c.removeOutbound(oldTag)
	if err != nil {
		return err
	}
	return nil
}

func (c *Controller) addNewTag(newNodeInfo *api.NodeInfo) (err error) {
	if newNodeInfo.NodeType != "Shadowsocks-Plugin" {
		inboundConfig, err := InboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {
			return err
		}
		err = c.addInbound(inboundConfig)
		if err != nil {

			return err
		}
		outBoundConfig, err := OutboundBuilder(c.config, newNodeInfo, c.Tag)
		if err != nil {

			return err
		}
		err = c.addOutbound(outBoundConfig)
		if err != nil {

			return err
		}

	} else {
		return c.addInboundForSSPlugin(*newNodeInfo)
	}
	return nil
}

func (c *Controller) addInboundForSSPlugin(newNodeInfo api.NodeInfo) (err error) {
	// Shadowsocks-Plugin require a separate inbound for other TransportProtocol likes: ws, grpc
	fakeNodeInfo := newNodeInfo
	fakeNodeInfo.TransportProtocol = "tcp"
	fakeNodeInfo.EnableTLS = false
	// Add a regular Shadowsocks inbound and outbound
	inboundConfig, err := InboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err := OutboundBuilder(c.config, &fakeNodeInfo, c.Tag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	// Add an inbound for upper streaming protocol
	fakeNodeInfo = newNodeInfo
	fakeNodeInfo.Port++
	fakeNodeInfo.NodeType = "dokodemo-door"
	dokodemoTag := fmt.Sprintf("dokodemo-door_%s+1", c.Tag)
	inboundConfig, err = InboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {
		return err
	}
	err = c.addInbound(inboundConfig)
	if err != nil {

		return err
	}
	outBoundConfig, err = OutboundBuilder(c.config, &fakeNodeInfo, dokodemoTag)
	if err != nil {

		return err
	}
	err = c.addOutbound(outBoundConfig)
	if err != nil {

		return err
	}
	return nil
}

func (c *Controller) addNewUser(userInfo *[]api.UserInfo, nodeInfo *api.NodeInfo) (err error) {
	users := make([]*protocol.User, 0)
	switch nodeInfo.NodeType {
	case "V2ray", "Vmess", "Vless":
		// Same condition as InboundBuilder: V2ray nodes pick vless via
		// EnableVless, so the user accounts must match the inbound protocol.
		if (nodeInfo.NodeType == "V2ray" && nodeInfo.EnableVless) || nodeInfo.NodeType == "Vless" {
			users = c.buildVlessUser(userInfo)
		} else {
			users = c.buildVmessUser(userInfo)
		}
	case "Trojan":
		users = c.buildTrojanUser(userInfo)
	case "Hysteria":
		users = c.buildHysteriaUser(userInfo)
	case "Shadowsocks":
		users = c.buildSSUser(userInfo, nodeInfo.CypherMethod)
	case "Shadowsocks-Plugin":
		users = c.buildSSPluginUser(userInfo)
	default:
		return fmt.Errorf("unsupported node type: %s", nodeInfo.NodeType)
	}

	err = c.addUsers(users, c.Tag)
	if err != nil {
		return err
	}
	c.logger.Printf("Added %d new users", len(*userInfo))
	return nil
}

func compareUserList(old, new *[]api.UserInfo) (deleted, added []api.UserInfo) {
	mSrc := make(map[api.UserInfo]byte) // 按源数组建索引
	mAll := make(map[api.UserInfo]byte) // 源+目所有元素建索引

	var set []api.UserInfo // 交集

	// 1.源数组建立map
	for _, v := range *old {
		mSrc[v] = 0
		mAll[v] = 0
	}
	// 2.目数组中，存不进去，即重复元素，所有存不进去的集合就是并集
	for _, v := range *new {
		l := len(mAll)
		mAll[v] = 1
		if l != len(mAll) { // 长度变化，即可以存
			l = len(mAll)
		} else { // 存不了，进并集
			set = append(set, v)
		}
	}
	// 3.遍历交集，在并集中找，找到就从并集中删，删完后就是补集（即并-交=所有变化的元素）
	for _, v := range set {
		delete(mAll, v)
	}
	// 4.此时，mall是补集，所有元素去源中找，找到就是删除的，找不到的必定能在目数组中找到，即新加的
	for v := range mAll {
		_, exist := mSrc[v]
		if exist {
			deleted = append(deleted, v)
		} else {
			added = append(added, v)
		}
	}

	return deleted, added
}

// limitUserLocked records a speed-limited user. Callers must hold c.trafficMu.
func limitUserLocked(c *Controller, user api.UserInfo, silentUsers *[]api.UserInfo) {
	c.limitedUsers[user] = LimitInfo{
		end:               time.Now().Unix() + int64(c.config.AutoSpeedLimitConfig.LimitDuration*60),
		currentSpeedLimit: c.config.AutoSpeedLimitConfig.LimitSpeed,
		originSpeedLimit:  user.SpeedLimit,
	}
	c.logger.Printf("Limit User: %s Speed: %d End: %s", c.buildUserTag(&user), c.config.AutoSpeedLimitConfig.LimitSpeed, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
	user.SpeedLimit = uint64((c.config.AutoSpeedLimitConfig.LimitSpeed * 1000000) / 8)
	*silentUsers = append(*silentUsers, user)
}

// defaultUpdatePeriodic is the final fallback interval when neither the local
// config nor the panel provides one.
const defaultUpdatePeriodic = 60

// firstNonZero returns the first value greater than zero.
func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}

// userInfoMonitor runs on the pull cadence: it reads per-user traffic counters,
// applies auto speed-limit decisions and stashes the counters as pending traffic
// for pushMonitor to report and reset.
func (c *Controller) userInfoMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(defaultUpdatePeriodic)*time.Second {
		return nil
	}

	// Unlock expired limited users
	c.trafficMu.Lock()
	unlockExpiredLimitsLocked(c)
	c.trafficMu.Unlock()

	// Snapshot shared state under the same lock the writer uses.
	c.trafficMu.Lock()
	nodePullInterval := c.nodeInfo.PullInterval
	userListSnapshot := *c.userList
	// Unlock below after building userTraffic; keep critical section small.
	c.trafficMu.Unlock()

	// Get User traffic. Stats counters and the user-list snapshot are read
	// without trafficMu; only the auto-limit decisions and the pendingTraffic
	// hand-off below need the lock.
	var userTraffic []api.UserTraffic
	var upCounterList []stats.Counter
	var downCounterList []stats.Counter
	AutoSpeedLimit := int64(c.config.AutoSpeedLimitConfig.Limit)
	UpdatePeriodic := int64(firstNonZero(c.config.PullInterval, nodePullInterval, c.config.UpdatePeriodic, defaultUpdatePeriodic))
	limitedUsers := make([]api.UserInfo, 0)
	overSpeeds := make([]api.UserInfo, 0)
	for _, user := range userListSnapshot {
		up, down, upCounter, downCounter := c.getTraffic(c.buildUserTag(&user))
		if up > 0 || down > 0 {
			if AutoSpeedLimit > 0 &&
				(down > AutoSpeedLimit*1000000*UpdatePeriodic/8 || up > AutoSpeedLimit*1000000*UpdatePeriodic/8) {
				overSpeeds = append(overSpeeds, user)
			}
			userTraffic = append(userTraffic, api.UserTraffic{
				UID:      user.UID,
				Email:    user.Email,
				Upload:   up,
				Download: down})

			if upCounter != nil {
				upCounterList = append(upCounterList, upCounter)
			}
			if downCounter != nil {
				downCounterList = append(downCounterList, downCounter)
			}
		}
	}

	c.trafficMu.Lock()
	// Apply warn/limit decisions for over-speed users.
	for _, user := range overSpeeds {
		if _, limited := c.limitedUsers[user]; limited {
			continue
		}
		if c.config.AutoSpeedLimitConfig.WarnTimes == 0 {
			limitUserLocked(c, user, &limitedUsers)
		} else {
			c.warnedUsers[user] += 1
			if c.warnedUsers[user] > c.config.AutoSpeedLimitConfig.WarnTimes {
				limitUserLocked(c, user, &limitedUsers)
				delete(c.warnedUsers, user)
			}
		}
	}

	// Hand the read counters over to the push side. Replace any stale batch:
	// xray counters are only reset after a successful report, so a fresh
	// reading is always a superset of a pending one — merging would double-count.
	if len(userTraffic) > 0 {
		c.pendingTraffic = &pendingTraffic{
			userTraffic:  userTraffic,
			upCounters:   upCounterList,
			downCounters: downCounterList,
		}
	}
	tag := c.Tag
	c.trafficMu.Unlock()

	if len(limitedUsers) > 0 {
		if err := c.UpdateInboundLimiter(tag, &limitedUsers); err != nil {
			c.logger.Print(err)
		}
	}

	return nil
}

// unlockExpiredLimitsLocked releases users whose auto-limit duration expired.
// Callers must hold c.trafficMu.
func unlockExpiredLimitsLocked(c *Controller) {
	if c.config.AutoSpeedLimitConfig.Limit > 0 && len(c.limitedUsers) > 0 {
		c.logger.Printf("Limited users:")
		toReleaseUsers := make([]api.UserInfo, 0)
		for user, limitInfo := range c.limitedUsers {
			if time.Now().Unix() > limitInfo.end {
				user.SpeedLimit = limitInfo.originSpeedLimit
				toReleaseUsers = append(toReleaseUsers, user)
				c.logger.Printf("User: %s Speed: %d End: nil (Unlimit)", c.buildUserTag(&user), user.SpeedLimit)
				delete(c.limitedUsers, user)
			} else {
				c.logger.Printf("User: %s Speed: %d End: %s", c.buildUserTag(&user), limitInfo.currentSpeedLimit, time.Unix(c.limitedUsers[user].end, 0).Format("01-02 15:04:05"))
			}
		}
		if len(toReleaseUsers) > 0 {
			// UpdateInboundLimiter only touches the dispatcher limiter maps,
			// not controller state guarded by trafficMu.
			if err := c.UpdateInboundLimiter(c.Tag, &toReleaseUsers); err != nil {
				c.logger.Print(err)
			}
		}
	}
}

// pushMonitor runs on the push cadence: reports node status, pending per-user
// traffic (resetting xray counters only after a successful report), online
// devices and audit-rule hits to the panel.
func (c *Controller) pushMonitor() (err error) {
	// delay to start
	if time.Since(c.startAt) < time.Duration(defaultUpdatePeriodic)*time.Second {
		return nil
	}

	// Snapshot the tag once; nodeInfoMonitor may replace it concurrently.
	c.trafficMu.Lock()
	tag := c.Tag
	c.trafficMu.Unlock()

	// Get server status
	CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
	if err != nil {
		c.logger.Print(err)
	}
	err = c.apiClient.ReportNodeStatus(
		&api.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	if err != nil {
		c.logger.Print(err)
	}

	// Take pending traffic collected by the pull side
	c.trafficMu.Lock()
	batch := c.pendingTraffic
	c.pendingTraffic = nil
	c.trafficMu.Unlock()

	var userTraffic []api.UserTraffic
	if batch != nil && len(batch.userTraffic) > 0 {
		userTraffic = batch.userTraffic
		var reportErr error // Define an empty error
		if !c.config.DisableUploadTraffic {
			reportErr = c.apiClient.ReportUserTraffic(&userTraffic)
		}
		if reportErr != nil {
			// Discard the batch: counters were NOT reset, so the next pull-side
			// reading is cumulative and contains this traffic. Restoring stale
			// counter references would under-report the growth since snapshot.
			c.logger.Print(reportErr)
		} else {
			c.resetTraffic(&batch.upCounters, &batch.downCounters)
		}
	}

	// Report Online info
	if onlineDevice, err := c.GetOnlineDevice(tag); err != nil {
		c.logger.Print(err)
	} else if len(*onlineDevice) > 0 {
		// Only report user has traffic > threshold to allow ping test
		var result []api.OnlineUser
		var nocountUID = make(map[int]struct{})
		for _, traffic := range userTraffic {
			total := traffic.Upload + traffic.Download
			if total < int64(c.config.DeviceOnlineMinTraffic*1000) {
				nocountUID[traffic.UID] = struct{}{}
			}
		}
		for _, online := range *onlineDevice {
			if _, ok := nocountUID[online.UID]; !ok {
				result = append(result, online)
			}
		}

		if err = c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.Print(err)
		} else {
			log.Printf("Total %d online users, %d Reported", len(*onlineDevice), len(result))
		}
	}

	// Report Illegal user
	if detectResult, err := c.GetDetectResult(tag); err != nil {
		c.logger.Print(err)
	} else if len(*detectResult) > 0 {
		if err = c.apiClient.ReportIllegal(detectResult); err != nil {
			c.logger.Print(err)
		} else {
			c.logger.Printf("Report %d illegal behaviors", len(*detectResult))
		}

	}
	return nil
}

func (c *Controller) buildNodeTag() string {
	return fmt.Sprintf("%s_%s_%d", c.nodeInfo.NodeType, c.config.ListenIP, c.nodeInfo.Port)
}

// func (c *Controller) logPrefix() string {
// 	return fmt.Sprintf("[%s] %s(ID=%d)", c.clientInfo.APIHost, c.nodeInfo.NodeType, c.nodeInfo.NodeID)
// }

// Check Cert
func (c *Controller) certMonitor() error {
	c.trafficMu.Lock()
	enableTLS := c.nodeInfo.EnableTLS
	c.trafficMu.Unlock()
	if enableTLS && !c.config.EnableREALITY {
		switch c.config.CertConfig.CertMode {
		case "dns", "http", "tls":
			lego, err := mylego.New(c.config.CertConfig)
			if err != nil {
				c.logger.Print(err)
			}
			// Xray-core supports the OcspStapling certification hot renew
			_, _, _, err = lego.RenewCert()
			if err != nil {
				c.logger.Print(err)
			}
		}
	}
	return nil
}
