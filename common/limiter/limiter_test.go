package limiter

import (
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
