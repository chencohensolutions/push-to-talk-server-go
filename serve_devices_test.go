package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestYourDevices: a phone lists its user's devices with when each was last seen, revokes another of them, and is
// refused revoking itself or a device that isn't its user's.
func TestYourDevices(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	env.addUser(t, "dana")
	first, _, _ := env.device(t, "hen")
	second, _, _ := env.device(t, "hen")
	danaPhone, _, _ := env.device(t, "dana")
	env.graphql(t, second, `{ me { user } }`, nil) // the second phone is seen too

	r := env.graphql(t, first, `{ devices { deviceNumber lastSeenAt keyProtection current } }`, nil)
	if len(r.Errors) > 0 {
		t.Fatalf("devices: %+v", r.Errors)
	}
	var devices []struct {
		DeviceNumber  int
		LastSeenAt    *string
		KeyProtection string
		Current       bool
	}
	json.Unmarshal(r.Data["devices"], &devices)
	if len(devices) != 2 || !devices[0].Current || devices[1].Current || devices[0].LastSeenAt == nil ||
		devices[1].LastSeenAt == nil || devices[0].KeyProtection == "" {
		t.Fatalf("devices: %s", r.Data["devices"])
	}

	revoke := func(client *http.Client, number int) string {
		t.Helper()
		r := env.graphql(t, client, `mutation($n: Int!) { revokeMyDevice(deviceNumber: $n) }`, map[string]any{"n": number})
		if len(r.Errors) > 0 {
			t.Fatalf("revokeMyDevice: %+v", r.Errors)
		}
		var result string
		json.Unmarshal(r.Data["revokeMyDevice"], &result)
		return result
	}
	if got := revoke(first, 1); got != "CURRENT_DEVICE" {
		t.Fatalf("revoking itself: %s", got)
	}
	if got := revoke(danaPhone, 2); got != "NOT_FOUND" {
		t.Fatalf("dana revoking a number she doesn't have: %s", got)
	}
	if got := revoke(first, 2); got != "REVOKED" {
		t.Fatalf("revoking the second phone: %s", got)
	}
	if r := env.graphql(t, second, `{ me { user } }`, nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("the revoked phone got HTTP %d", r.Status)
	}
	if got := revoke(first, 2); got != "NOT_FOUND" {
		t.Fatalf("revoking it again: %s", got)
	}
	if r := env.graphql(t, danaPhone, `{ me { user } }`, nil); r.Status != http.StatusOK {
		t.Fatalf("dana's phone got HTTP %d", r.Status)
	}
	r = env.graphql(t, first, `{ devices { deviceNumber } }`, nil)
	json.Unmarshal(r.Data["devices"], &devices)
	if len(devices) != 1 || devices[0].DeviceNumber != 1 {
		t.Fatalf("devices after: %s", r.Data["devices"])
	}
}
