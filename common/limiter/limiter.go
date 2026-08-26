// Package limiter is to control the links that go into the dispatcher
package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	goCacheStore "github.com/eko/gocache/store/go_cache/v4"
	redisStore "github.com/eko/gocache/store/redis/v4"
	goCache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/aprpure/XrayR/api"
	"golang.org/x/time/rate"
)

type UserInfo struct {
	UID         int
	SpeedLimit  uint64
	DeviceLimit int
}

type InboundInfo struct {
	Tag            string
	NodeSpeedLimit uint64
	UserInfo       *sync.Map // Key: Email value: UserInfo
	BucketHub      *sync.Map // key: Email, value: *rate.Limiter
	UserOnlineIP   *sync.Map // Key: Email, value: {Key: IP, value: UID}
	GlobalLimit    struct {
		config         *GlobalDeviceLimitConfig
		globalOnlineIP *marshaler.Marshaler
		mu             sync.Mutex // serializes read-modify-write of cached IP maps and their async push back to the cache
	}
	AliveList     atomic.Pointer[map[int]int] // Key: Uid, value: alive_ip; published atomically so the dispatch path can read it lock-free
	OldUserOnline *sync.Map                   // Key: Ip, value: Uid
}

type Limiter struct {
	InboundInfo *sync.Map // Key: Tag, Value: *InboundInfo
}

func New() *Limiter {
	return &Limiter{
		InboundInfo: new(sync.Map),
	}
}

func (l *Limiter) AddInboundLimiter(tag string, nodeSpeedLimit uint64, userList *[]api.UserInfo, globalLimit *GlobalDeviceLimitConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		UserOnlineIP:   new(sync.Map),
		OldUserOnline:  new(sync.Map),
	}

	if globalLimit != nil && globalLimit.Enable {
		inboundInfo.GlobalLimit.config = globalLimit

		// init local store
		gs := goCacheStore.NewGoCache(goCache.New(time.Duration(globalLimit.Expiry)*time.Second, 1*time.Minute))

		// init redis store
		rs := redisStore.NewRedis(redis.NewClient(
			&redis.Options{
				Network:  globalLimit.RedisNetwork,
				Addr:     globalLimit.RedisAddr,
				Username: globalLimit.RedisUsername,
				Password: globalLimit.RedisPassword,
				DB:       globalLimit.RedisDB,
			}),
			store.WithExpiration(time.Duration(globalLimit.Expiry)*time.Second))

		// init chained cache. First use local go-cache, if go-cache is nil, then use redis cache
		cacheManager := cache.NewChain[any](
			cache.New[any](gs), // go-cache is priority
			cache.New[any](rs),
		)
		inboundInfo.GlobalLimit.globalOnlineIP = marshaler.New(cacheManager)
	}

	userMap := new(sync.Map)
	for _, u := range *userList {
		userMap.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), UserInfo{
			UID:         u.UID,
			SpeedLimit:  u.SpeedLimit,
			DeviceLimit: u.DeviceLimit,
		})
	}
	inboundInfo.UserInfo = userMap
	l.InboundInfo.Store(tag, inboundInfo) // Replace the old inbound info
	return nil
}

func (l *Limiter) UpdateInboundLimiter(tag string, updatedUserList *[]api.UserInfo) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Update User info
		for _, u := range *updatedUserList {
			inboundInfo.UserInfo.Store(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID), UserInfo{
				UID:         u.UID,
				SpeedLimit:  u.SpeedLimit,
				DeviceLimit: u.DeviceLimit,
			})
			// Update old limiter bucket
			limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
			if limit > 0 {
				if bucket, ok := inboundInfo.BucketHub.Load(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID)); ok {
					limiter := bucket.(*rate.Limiter)
					limiter.SetLimit(rate.Limit(limit))
					limiter.SetBurst(int(limit))
				}
			} else {
				inboundInfo.BucketHub.Delete(fmt.Sprintf("%s|%s|%d", tag, u.Email, u.UID))
			}
		}
	} else {
		return fmt.Errorf("no such inbound in limiter: %s", tag)
	}
	return nil
}

func (l *Limiter) DeleteInboundLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

// SetAliveList atomically replaces the alive-IP map for an inbound. The map is
// published as-is and must not be mutated afterwards.
func (l *Limiter) SetAliveList(tag string, alive map[int]int) error {
	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		inboundInfo.AliveList.Store(&alive)
		return nil
	}
	return fmt.Errorf("no such inbound in limiter: %s", tag)
}

func (l *Limiter) GetOnlineDevice(tag string) (*[]api.OnlineUser, error) {
	var onlineUser []api.OnlineUser

	if value, ok := l.InboundInfo.Load(tag); ok {
		inboundInfo := value.(*InboundInfo)
		// Clear Speed Limiter bucket for users who are not online
		inboundInfo.BucketHub.Range(func(key, value interface{}) bool {
			email := key.(string)
			if _, exists := inboundInfo.UserOnlineIP.Load(email); !exists {
				inboundInfo.BucketHub.Delete(email)
			}
			return true
		})
		onlineIPs := make(map[string]struct{})
		inboundInfo.UserOnlineIP.Range(func(key, value interface{}) bool {
			email := key.(string)
			ipMap := value.(*sync.Map)
			ipMap.Range(func(key, value interface{}) bool {
				uid := value.(int)
				ip := key.(string)
				onlineIPs[ip] = struct{}{}
				inboundInfo.OldUserOnline.Store(ip, uid)
				onlineUser = append(onlineUser, api.OnlineUser{UID: uid, IP: ip})
				return true
			})
			inboundInfo.UserOnlineIP.Delete(email) // Reset online device
			return true
		})
		// Drop stale OldUserOnline entries: IPs that were online in a previous
		// period but not in this one. Without this the map only ever grows.
		inboundInfo.OldUserOnline.Range(func(key, value interface{}) bool {
			ip := key.(string)
			if _, online := onlineIPs[ip]; !online {
				inboundInfo.OldUserOnline.Delete(ip)
			}
			return true
		})
	} else {
		return nil, fmt.Errorf("no such inbound in limiter: %s", tag)
	}

	return &onlineUser, nil
}

func (l *Limiter) GetUserBucket(tag string, email string, ip string, isSourceTCP bool) (limiter *rate.Limiter, SpeedLimit bool, Reject bool) {
	if value, ok := l.InboundInfo.Load(tag); ok {
		var (
			userLimit        uint64 = 0
			deviceLimit, uid int
		)

		inboundInfo := value.(*InboundInfo)
		nodeLimit := inboundInfo.NodeSpeedLimit

		if v, ok := inboundInfo.UserInfo.Load(email); ok {
			u := v.(UserInfo)
			uid = u.UID
			userLimit = u.SpeedLimit
			deviceLimit = u.DeviceLimit
		}

		// Local device limit, only for TCP connection
		if isSourceTCP {
			var aliveIp int
			if alive := inboundInfo.AliveList.Load(); alive != nil {
				aliveIp = (*alive)[uid]
			}
			// Fast path: the user already has an online-IP map. Allocate only on
			// the first connection of a user (LoadOrStore fallback covers races).
			if v, ok := inboundInfo.UserOnlineIP.Load(email); ok {
				ipMap := v.(*sync.Map)
				// If this is a new ip
				if _, loaded := ipMap.LoadOrStore(ip, uid); !loaded {
					if deviceLimit > 0 && deviceLimit <= aliveIp {
						ipMap.Delete(ip)
						return nil, false, true
					}
				}
			} else {
				ipMap := new(sync.Map)
				ipMap.Store(ip, uid)
				if v, loaded := inboundInfo.UserOnlineIP.LoadOrStore(email, ipMap); loaded {
					// Lost the race: use the winner's map.
					winnerMap := v.(*sync.Map)
					if _, ok := winnerMap.LoadOrStore(ip, uid); !ok {
						if deviceLimit > 0 && deviceLimit <= aliveIp {
							winnerMap.Delete(ip)
							return nil, false, true
						}
					}
				} else if v, ok := inboundInfo.OldUserOnline.Load(ip); ok {
					if v.(int) == uid {
						inboundInfo.OldUserOnline.Delete(ip)
					}
				} else if deviceLimit > 0 && deviceLimit <= aliveIp {
					inboundInfo.UserOnlineIP.Delete(email)
					return nil, false, true
				}
			}
		}

		// GlobalLimit
		if inboundInfo.GlobalLimit.config != nil && inboundInfo.GlobalLimit.config.Enable {
			if reject := globalLimit(inboundInfo, email, uid, ip, deviceLimit); reject {
				return nil, false, true
			}
		}

		// Speed limit. Load-first: rate.NewLimiter is only allocated for users
		// without an existing bucket (or on a race, where LoadOrStore resolves it).
		limit := determineRate(nodeLimit, userLimit) // Determine the speed limit rate
		if limit > 0 {
			if v, ok := inboundInfo.BucketHub.Load(email); ok {
				return v.(*rate.Limiter), true, false
			}
			limiter := rate.NewLimiter(rate.Limit(limit), int(limit)) // Byte/s
			if v, ok := inboundInfo.BucketHub.LoadOrStore(email, limiter); ok {
				return v.(*rate.Limiter), true, false
			}
			return limiter, true, false
		}
		return nil, false, false
	} else {
		log.Error("Get Inbound Limiter information failed")
		return nil, false, false
	}
}

// globalGetReadTimeout caps how long a new connection waits on the cache read.
// The check is fail-open (cache errors never reject), so an unreachable redis
// must not stall connection setup for the full configured Timeout.
const globalGetReadTimeout = 300 * time.Millisecond

// Global device limit. Returns true when the device limit is reached.
func globalLimit(inboundInfo *InboundInfo, email string, uid int, ip string, deviceLimit int) bool {
	readCtx, cancel := context.WithTimeout(context.Background(), globalGetReadTimeout)
	defer cancel()

	// reformat email for unique key
	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(deviceLimit), 1)

	// Serialize the cache read-modify-write per inbound: concurrent connections
	// mutating the same cached map race each other and their async pushIP calls
	// overwrite one another, losing IPs.
	inboundInfo.GlobalLimit.mu.Lock()
	defer inboundInfo.GlobalLimit.mu.Unlock()

	v, err := inboundInfo.GlobalLimit.globalOnlineIP.Get(readCtx, uniqueKey, new(map[string]int))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			// If the email is a new device
			go pushIP(inboundInfo, uniqueKey, &map[string]int{ip: uid})
		} else {
			log.Error("cache service", err)
		}
		return false
	}

	ipMap := v.(*map[string]int)
	// Reject device reach limit directly
	if deviceLimit > 0 && len(*ipMap) > deviceLimit {
		return true
	}

	// If the ip is not in cache
	if _, ok := (*ipMap)[ip]; !ok {
		// Push a copy: the shared map keeps being mutated under mu while this
		// goroutine writes to the (possibly slow) remote cache.
		snapshot := make(map[string]int, len(*ipMap))
		for k, v := range *ipMap {
			snapshot[k] = v
		}
		snapshot[ip] = uid
		go func() {
			pushIP(inboundInfo, uniqueKey, &snapshot)
		}()
	}

	return false
}

// push the ip to cache
func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string]int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalLimit.config.Timeout)*time.Second)
	defer cancel()

	if err := inboundInfo.GlobalLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		log.Error("cache service", err)
	}
}

// determineRate returns the minimum non-zero rate
func determineRate(nodeLimit, userLimit uint64) (limit uint64) {
	if nodeLimit == 0 || userLimit == 0 {
		if nodeLimit > userLimit {
			return nodeLimit
		} else if nodeLimit < userLimit {
			return userLimit
		} else {
			return 0
		}
	} else {
		if nodeLimit > userLimit {
			return userLimit
		} else if nodeLimit < userLimit {
			return nodeLimit
		} else {
			return nodeLimit
		}
	}
}
