package limiter

import (
	"fmt"
	"sync"
	"testing"

	"github.com/aprpure/XrayR/api"
)

type apiUserInfo = api.UserInfo

type syncMap = sync.Map

// TestSetAliveListAndRead verifies the atomic publication of the alive-IP map:
// reads on the dispatch path see the latest snapshot, and a missing inbound
// returns an error instead of panicking.
func TestSetAliveListAndRead(t *testing.T) {
	l := New()
	const tag = "V2ray_1.2.3.4_443"
	if err := l.AddInboundLimiter(tag, 0, &[]apiUserInfo{}, nil); err != nil {
		t.Fatal(err)
	}

	alive := map[int]int{1: 3, 2: 0}
	if err := l.SetAliveList(tag, alive); err != nil {
		t.Fatal(err)
	}
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		t.Fatal("inbound missing")
	}
	inbound := v.(*InboundInfo)
	p := inbound.AliveList.Load()
	if p == nil {
		t.Fatal("alive list not published")
	}
	if (*p)[1] != 3 {
		t.Fatalf("alive[1] = %d, want 3", (*p)[1])
	}
	// nil-safe read path: a fresh inbound has no published map.
	if err := l.AddInboundLimiter(tag+"x", 0, &[]apiUserInfo{}, nil); err != nil {
		t.Fatal(err)
	}
	v2, _ := l.InboundInfo.Load(tag + "x")
	if v2.(*InboundInfo).AliveList.Load() != nil {
		t.Fatal("fresh inbound should have no alive list")
	}
	if err := l.SetAliveList("no-such-tag", alive); err == nil {
		t.Fatal("expected error for unknown tag")
	}
}

// TestGetOnlineDevicePrunesOldUserOnline verifies that IPs which were online in
// a previous period but not in the current one are dropped from OldUserOnline,
// so the map cannot grow without bound.
func TestGetOnlineDevicePrunesOldUserOnline(t *testing.T) {
	l := New()
	const tag = "V2ray_1.2.3.4_443"
	users := []api.UserInfo{{UID: 7, Email: "u7@x.user"}}
	if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	v, _ := l.InboundInfo.Load(tag)
	inbound := v.(*InboundInfo)

	// Period 1: ip "9.9.9.9" was online.
	ipMap1 := new(syncMap)
	ipMap1.Store("9.9.9.9", 7)
	inbound.UserOnlineIP.Store("u7@x.user", ipMap1)
	online, err := l.GetOnlineDevice(tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(*online) != 1 {
		t.Fatalf("period1 online = %d, want 1", len(*online))
	}
	if _, ok := inbound.OldUserOnline.Load("9.9.9.9"); !ok {
		t.Fatal("period1: old entry should exist")
	}

	// Period 2: user is offline; the stale entry must be pruned.
	online2, err := l.GetOnlineDevice(tag)
	if err != nil {
		t.Fatal(err)
	}
	if len(*online2) != 0 {
		t.Fatalf("period2 online = %d, want 0", len(*online2))
	}
	if _, ok := inbound.OldUserOnline.Load("9.9.9.9"); ok {
		t.Fatal("period2: stale OldUserOnline entry leaked")
	}
}

// newDeviceLimitFixture builds a limiter with a single device-limited user and
// an inbound whose alive list holds the given uid -> alive-IP count map. Pass a
// nil map to leave AliveList unpublished (the fail-open state).
//
// The email handed to GetUserBucket in production is the composite user tag
// built by the controller (buildUserTag: "{inboundTag}|{email}|{uid}"), which is
// both the UserInfo map key and the value stored in UserOnlineIP, so the
// fixture uses the same string throughout.
func newDeviceLimitFixture(t *testing.T, uid int, deviceLimit int, alive map[int]int) (*Limiter, string, string, *InboundInfo) {
	t.Helper()
	l := New()
	const tag = "Trojan_1.2.3.4_443"
	email := fmt.Sprintf("%s|u%d@x.user|%d", tag, uid, uid)
	users := []api.UserInfo{{UID: uid, Email: fmt.Sprintf("u%d@x.user", uid), DeviceLimit: deviceLimit}}
	if err := l.AddInboundLimiter(tag, 0, &users, nil); err != nil {
		t.Fatal(err)
	}
	if alive != nil {
		if err := l.SetAliveList(tag, alive); err != nil {
			t.Fatal(err)
		}
	}
	v, _ := l.InboundInfo.Load(tag)
	return l, tag, email, v.(*InboundInfo)
}

// TestGetUserBucketDeviceLimit pins the local device-limit gate. The gate only
// fires for a NEW local TCP IP when the panel-reported alive-IP count for the
// user has already reached deviceLimit; known IPs, previously-seen IPs, a
// missing alive list, and non-TCP sources are all allowed through.
func TestGetUserBucketDeviceLimit(t *testing.T) {
	const uid = 7

	tests := []struct {
		name        string
		deviceLimit int
		alive       map[int]int
		ip          string
		isSourceTCP bool
		seedOnline  bool // pre-populate UserOnlineIP with the same ip
		seedOld     bool // pre-populate OldUserOnline with the same ip
		wantReject  bool
	}{
		{
			name:        "new ip over limit is rejected",
			deviceLimit: 2,
			alive:       map[int]int{uid: 2},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			wantReject:  true,
		},
		{
			name:        "new ip under limit is allowed",
			deviceLimit: 3,
			alive:       map[int]int{uid: 2},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			wantReject:  false,
		},
		{
			name:        "no device limit is allowed",
			deviceLimit: 0,
			alive:       map[int]int{uid: 9},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			wantReject:  false,
		},
		{
			name:        "missing alive list fails open",
			deviceLimit: 1,
			alive:       nil,
			ip:          "1.2.3.4",
			isSourceTCP: true,
			wantReject:  false,
		},
		{
			name:        "uid absent from alive map fails open",
			deviceLimit: 1,
			alive:       map[int]int{999: 5},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			wantReject:  false,
		},
		{
			name:        "known ip reconnects even over limit",
			deviceLimit: 1,
			alive:       map[int]int{uid: 5},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			seedOnline:  true,
			wantReject:  false,
		},
		{
			name:        "previously seen ip gets a grace pass",
			deviceLimit: 1,
			alive:       map[int]int{uid: 5},
			ip:          "1.2.3.4",
			isSourceTCP: true,
			seedOld:     true,
			wantReject:  false,
		},
		{
			name:        "non tcp source skips the gate entirely",
			deviceLimit: 1,
			alive:       map[int]int{uid: 5},
			ip:          "1.2.3.4",
			isSourceTCP: false,
			wantReject:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, tag, email, inbound := newDeviceLimitFixture(t, uid, tc.deviceLimit, tc.alive)

			if tc.seedOnline {
				ipMap := new(syncMap)
				ipMap.Store(tc.ip, uid)
				inbound.UserOnlineIP.Store(email, ipMap)
			}
			if tc.seedOld {
				inbound.OldUserOnline.Store(tc.ip, uid)
			}

			_, _, reject := l.GetUserBucket(tag, email, tc.ip, tc.isSourceTCP)
			if reject != tc.wantReject {
				t.Fatalf("Reject = %v, want %v", reject, tc.wantReject)
			}
		})
	}
}

// TestGetUserBucketDeviceLimitConsumesOldIP verifies the OldUserOnline grace
// path also removes the entry, so a returning IP gets exactly one free pass
// rather than a permanent exemption.
func TestGetUserBucketDeviceLimitConsumesOldIP(t *testing.T) {
	const uid = 7
	l, tag, email, inbound := newDeviceLimitFixture(t, uid, 1, map[int]int{uid: 5})
	inbound.OldUserOnline.Store("1.2.3.4", uid)

	if _, _, reject := l.GetUserBucket(tag, email, "1.2.3.4", true); reject {
		t.Fatal("first connection from a previously seen IP should be allowed")
	}
	if _, ok := inbound.OldUserOnline.Load("1.2.3.4"); ok {
		t.Fatal("grace entry should be consumed by the first connection")
	}
	// The IP is now in UserOnlineIP, so it stays allowed as a known IP.
	if _, _, reject := l.GetUserBucket(tag, email, "1.2.3.4", true); reject {
		t.Fatal("known IP should remain allowed after the grace pass")
	}
}
