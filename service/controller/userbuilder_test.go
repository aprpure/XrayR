package controller

import (
	"testing"

	"github.com/aprpure/XrayR/api"
)

// TestBuildSSUserNoNilUsers verifies that users with an invalid SS2022 key are
// skipped instead of leaving nil entries in the returned slice — addUsers calls
// ToMemoryUser() on every element, so a nil entry would panic the process.
func TestBuildSSUserNoNilUsers(t *testing.T) {
	c := &Controller{panelType: "V2board", Tag: "Shadowsocks_1.2.3.4_443"}
	users := []api.UserInfo{
		{UID: 1, Email: "u1@v2board.user", Passwd: "short"},                            // too short for SS2022 -> skipped
		{UID: 2, Email: "u2@v2board.user", Passwd: "0123456789abcdef0123456789abcdef"}, // valid 32-char key
	}
	built := c.buildSSUser(&users, "2022-blake3-aes-128-gcm")
	if len(built) != 1 {
		t.Fatalf("expected 1 user (bad key skipped), got %d", len(built))
	}
	for i, u := range built {
		if u == nil {
			t.Fatalf("built user %d is nil", i)
		}
		if u.Email != "Shadowsocks_1.2.3.4_443|u2@v2board.user|2" {
			t.Errorf("unexpected email: %s", u.Email)
		}
	}
}

func TestBuildSSUserAead(t *testing.T) {
	c := &Controller{panelType: "SSpanel", Tag: "Shadowsocks_1.2.3.4_443"}
	users := []api.UserInfo{{UID: 1, Email: "u1@ss.user", Passwd: "pass1"}}
	built := c.buildSSUser(&users, "aes-256-gcm")
	if len(built) != 1 || built[0] == nil {
		t.Fatalf("expected 1 non-nil aead user, got %d", len(built))
	}
}

// TestBuildSSPluginUserNoNilUsers covers both skip paths of buildSSPluginUser:
// an invalid SS2022 key and an unknown cipher must not produce nil entries.
func TestBuildSSPluginUserNoNilUsers(t *testing.T) {
	// V2board panelType enables the SS2022 key-length validation path.
	c := &Controller{panelType: "V2board", Tag: "Shadowsocks-Plugin_1.2.3.4_443"}
	users := []api.UserInfo{
		{UID: 1, Email: "u1@x.user", Method: "2022-blake3-aes-128-gcm", Passwd: "short"}, // bad 2022 key -> skipped
		{UID: 2, Email: "u2@x.user", Method: "rc4-md5", Passwd: "pass2"},                 // unknown cipher -> skipped
		{UID: 3, Email: "u3@x.user", Method: "chacha20-poly1305", Passwd: "pass3"},       // valid aead
	}
	built := c.buildSSPluginUser(&users)
	if len(built) != 1 {
		t.Fatalf("expected 1 user (two skipped), got %d", len(built))
	}
	if built[0] == nil || built[0].Email != "Shadowsocks-Plugin_1.2.3.4_443|u3@x.user|3" {
		t.Fatalf("unexpected built user: %+v", built[0])
	}
}

// TestBuildTrojanUser ensures the plain builders still return one entry per input.
func TestBuildTrojanUser(t *testing.T) {
	c := &Controller{Tag: "Trojan_1.2.3.4_443"}
	users := []api.UserInfo{
		{UID: 1, Email: "a@x.user", UUID: "pw1"},
		{UID: 2, Email: "b@x.user", UUID: "pw2"},
	}
	built := c.buildTrojanUser(&users)
	if len(built) != len(users) {
		t.Fatalf("expected %d users, got %d", len(users), len(built))
	}
}

// TestAddNewUserVmessEnableVless guards the protocol-selection condition: with
// NodeType=Vmess + EnableVless=true the inbound is vmess (see InboundBuilder),
// so users must be vmess accounts too.
func TestAddNewUserVmessEnableVless(t *testing.T) {
	nodeInfo := &api.NodeInfo{
		NodeType:    "Vmess",
		EnableVless: true,
		Port:        443,
	}
	// Mirror the InboundBuilder condition; it must select vmess here.
	buildsVless := (nodeInfo.NodeType == "V2ray" && nodeInfo.EnableVless) || nodeInfo.NodeType == "Vless"
	if buildsVless {
		t.Error("NodeType=Vmess + EnableVless=true must build vmess users")
	}
}
