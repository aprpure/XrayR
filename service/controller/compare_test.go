package controller

import (
	"testing"

	"github.com/aprpure/XrayR/api"
)

func TestCompareUserList(t *testing.T) {
	old := &[]api.UserInfo{
		{UID: 1, Email: "a@x.user", UUID: "ua"},
		{UID: 2, Email: "b@x.user", UUID: "ub"},
		{UID: 3, Email: "c@x.user", UUID: "uc"},
	}
	new := &[]api.UserInfo{
		{UID: 2, Email: "b@x.user", UUID: "ub"},   // unchanged
		{UID: 3, Email: "c2@x.user", UUID: "uc2"}, // changed email+uuid -> delete + add
		{UID: 4, Email: "d@x.user", UUID: "ud"},   // added
	}

	deleted, added := compareUserList(old, new)
	if len(deleted) != 2 || len(added) != 2 {
		t.Fatalf("expected 2 deleted / 2 added, got %d / %d", len(deleted), len(added))
	}

	delUIDs := map[int]bool{}
	for _, u := range deleted {
		delUIDs[u.UID] = true
	}
	addUIDs := map[int]bool{}
	for _, u := range added {
		addUIDs[u.UID] = true
	}
	if !delUIDs[1] || !delUIDs[3] {
		t.Errorf("expected UIDs 1,3 deleted, got %+v", deleted)
	}
	if !addUIDs[3] || !addUIDs[4] {
		t.Errorf("expected UIDs 3,4 added, got %+v", added)
	}
}

func TestCompareUserListNoChange(t *testing.T) {
	users := &[]api.UserInfo{{UID: 1, Email: "a@x.user", UUID: "u"}}
	deleted, added := compareUserList(users, users)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("identical lists must diff to zero, got %d deleted / %d added", len(deleted), len(added))
	}

	empty := &[]api.UserInfo{}
	deleted, added = compareUserList(empty, empty)
	if len(deleted) != 0 || len(added) != 0 {
		t.Fatalf("empty lists must diff to zero")
	}
}

// TestCompareUserListDuplicatesInNew mirrors the old implementation's behavior:
// duplicate entries within the new list are collapsed by the set.
func TestCompareUserListDuplicatesInNew(t *testing.T) {
	old := &[]api.UserInfo{}
	new := &[]api.UserInfo{
		{UID: 1, Email: "a@x.user", UUID: "u"},
		{UID: 1, Email: "a@x.user", UUID: "u"},
	}
	deleted, added := compareUserList(old, new)
	if len(deleted) != 0 || len(added) != 1 {
		t.Fatalf("duplicate new entries must collapse to one add, got %d deleted / %d added", len(deleted), len(added))
	}
}
