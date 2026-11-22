package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

type groupAnswer struct {
	ID      string
	Owner   string
	Members []string
	Invited []string
}

const groupFields = `{ id owner members invited createdAt }`

// groupCall runs a group mutation or query field with variables, and answers its data and error code.
func (e *testEnv) groupCall(t *testing.T, p *phone, op string, vars map[string]any) (json.RawMessage, string) {
	t.Helper()
	r := e.graphql(t, p.client, op, vars)
	for _, v := range r.Data {
		return v, errorCode(r)
	}
	return nil, errorCode(r)
}

func (e *testEnv) createGroup(t *testing.T, p *phone) groupAnswer {
	t.Helper()
	data, code := e.groupCall(t, p, `mutation { createGroup `+groupFields+` }`, nil)
	var g groupAnswer
	json.Unmarshal(data, &g)
	if code != "" || len(g.ID) != 32 {
		t.Fatalf("createGroup: %s %s", data, code)
	}
	return g
}

// groupOp runs mutation field(group, user) (user left out when "") and answers the group and the error code.
func (e *testEnv) groupOp(t *testing.T, p *phone, field, group, user string) (groupAnswer, string) {
	t.Helper()
	vars := map[string]any{"g": group}
	args, params := "group: $g", "$g: ID!"
	if user != "" {
		vars["u"] = user
		args, params = args+", user: $u", params+", $u: String!"
	}
	selection := groupFields
	if field == "leaveGroup" || field == "deleteGroup" {
		selection = ""
	}
	data, code := e.groupCall(t, p, fmt.Sprintf(`mutation(%s) { %s(%s) %s }`, params, field, args, selection), vars)
	var g groupAnswer
	json.Unmarshal(data, &g)
	return g, code
}

// envelopeOf is the next envelope of kind, passing over the others.
func (s *socket) envelopeOf(t *testing.T, kind pb.Envelope_Type) *pb.Envelope {
	t.Helper()
	for {
		e := s.envelope(t)
		s.ack(t, e.Id)
		if e.Type == kind {
			return e
		}
	}
}

// groupSend sends one SENDER_KEY_MESSAGE to group, for the devices named.
func (s *socket) groupSend(t *testing.T, group string, devices map[string][]*phone) *pb.SendResult {
	t.Helper()
	send := &pb.Send{ClientId: fmt.Sprint(time.Now().UnixNano()), Group: group, PushKind: pb.PushKind_PUSH_MESSAGE,
		Envelopes: []*pb.Envelope{{Type: pb.Envelope_SENDER_KEY_MESSAGE, Ciphertext: []byte("sender key ciphertext")}}}
	for user, phones := range devices {
		list := &pb.UserDevices{User: user}
		for _, p := range phones {
			list.Devices = append(list.Devices, &pb.ActiveDevice{DeviceNumber: uint32(p.number)})
		}
		send.GroupDevices = append(send.GroupDevices, list)
	}
	s.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	return s.next(t, "send_result").GetSendResult()
}

// Phase 4 from the server's side: an owner makes a group of two of its contacts who never paired with each other,
// they accept, and then a group Send reaches every member device once; members can reach each other to hand out
// sender keys; a member taken out gets nothing more, and deleting the group ends it for everyone.
func TestAGroupOfThree(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana", "noa", "eli")
	hen, dana, noa, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "noa"), env.phone(t, "eli")
	for _, p := range []*phone{hen, dana, noa, eli} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket, danaSocket, noaSocket := env.socket(t, hen), env.socket(t, dana), env.socket(t, noa)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	env.pair(t, noa, []store.Device{dev(noa)}, hen, henSocket)
	eliSocket := env.socket(t, eli)
	env.pair(t, eli, []store.Device{dev(eli)}, hen, henSocket)

	g := env.createGroup(t, hen)
	if g.Owner != "hen" || strings.Join(g.Members, ",") != "hen" {
		t.Fatalf("a new group: %+v", g)
	}
	// Only the owner invites, and only its contacts.
	if _, code := env.groupOp(t, dana, "inviteToGroup", g.ID, "noa"); code != "NO_GROUP" {
		t.Fatalf("someone outside inviting: %s", code)
	}
	env.addUser(t, "stranger")
	if _, code := env.groupOp(t, hen, "inviteToGroup", g.ID, "stranger"); code != "NOT_PAIRED" {
		t.Fatalf("inviting a user who isn't a contact: %s", code)
	}
	for _, user := range []string{"dana", "noa"} {
		if _, code := env.groupOp(t, hen, "inviteToGroup", g.ID, user); code != "" {
			t.Fatalf("invite %s: %s", user, code)
		}
	}
	if e := danaSocket.envelopeOf(t, pb.Envelope_GROUP_CHANGED); e.Group != g.ID || e.SenderUser != "hen" {
		t.Fatalf("dana's GROUP_CHANGED: %v", e)
	}
	noaSocket.envelopeOf(t, pb.Envelope_GROUP_CHANGED)
	if _, code := env.groupOp(t, dana, "inviteToGroup", g.ID, "noa"); code != "NOT_OWNER" {
		t.Fatalf("an invited user inviting: %s", code)
	}

	// Invited isn't in yet: dana and noa, who never paired, can't reach each other, and a group Send skips them.
	if _, problem := env.bundles(t, dana, "noa", ""); !strings.HasPrefix(problem, "NOT_PAIRED") {
		t.Fatalf("bundles of an invited user: %s", problem)
	}
	if r := danaSocket.groupSend(t, g.ID, nil); r.Status != pb.SendResult_NOT_MEMBER {
		t.Fatalf("a group Send by an invited user: %v", r)
	}
	if r := henSocket.groupSend(t, g.ID, nil); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a group Send with nobody else in: %v", r)
	}

	for _, p := range []*phone{dana, noa} {
		if _, code := env.groupOp(t, p, "acceptGroupInvite", g.ID, ""); code != "" {
			t.Fatalf("%s accepting: %s", p.user, code)
		}
	}
	if _, code := env.groupOp(t, eli, "acceptGroupInvite", g.ID, ""); code != "NO_GROUP" {
		t.Fatalf("accepting without an invitation: %s", code)
	}
	data, _ := env.groupCall(t, noa, `{ groups `+groupFields+` }`, nil)
	var list []groupAnswer
	json.Unmarshal(data, &list)
	if len(list) != 1 || strings.Join(list[0].Members, ",") != "hen,dana,noa" || len(list[0].Invited) != 0 {
		t.Fatalf("noa's groups: %s", data)
	}

	// Members reach each other to hand out sender keys, though they aren't paired.
	if _, problem := env.bundles(t, dana, "noa", ""); problem != "" {
		t.Fatalf("bundles of a fellow member: %s", problem)
	}
	if r := danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, "", dev(noa)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a sender key to a fellow member: %v", r)
	}
	noaSocket.envelopeOf(t, pb.Envelope_PREKEY_MESSAGE)

	// A group Send must name every member device; then each gets one copy, with the group named.
	if r := henSocket.groupSend(t, g.ID, map[string][]*phone{"dana": {dana}}); r.Status != pb.SendResult_STALE_DEVICES {
		t.Fatalf("a group Send missing noa: %v", r)
	} else if len(r.Devices) != 3 || r.Devices[0].User != "dana" || r.Devices[1].User != "hen" || len(r.Devices[1].Devices) != 0 || r.Devices[2].User != "noa" {
		t.Fatalf("the devices of a STALE_DEVICES: %v", r.Devices)
	}
	if r := henSocket.groupSend(t, g.ID, map[string][]*phone{"dana": {dana}, "noa": {noa}, "eli": {eli}}); r.Status != pb.SendResult_STALE_DEVICES {
		t.Fatalf("a group Send naming someone outside: %v", r)
	}
	if r := henSocket.groupSend(t, g.ID, map[string][]*phone{"dana": {dana}, "noa": {noa}}); r.Status != pb.SendResult_ACCEPTED || len(r.EnvelopeIds) != 2 {
		t.Fatalf("a group Send: %v", r)
	}
	for _, s := range []*socket{danaSocket, noaSocket} {
		e := s.envelopeOf(t, pb.Envelope_SENDER_KEY_MESSAGE)
		if e.Group != g.ID || e.SenderUser != "hen" || string(e.Ciphertext) != "sender key ciphertext" {
			t.Fatalf("a group message: %v", e)
		}
	}
	if r := eliSocket.groupSend(t, g.ID, nil); r.Status != pb.SendResult_NOT_MEMBER {
		t.Fatalf("a group Send from outside: %v", r)
	}

	// A member who blocked the sender is left out of its group Sends.
	env.mutate(t, noa, "block", "dana")
	if r := danaSocket.groupSend(t, g.ID, map[string][]*phone{"hen": {hen}}); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a group Send leaving out who blocked: %v", r)
	}
	env.mutate(t, noa, "unblock", "dana")

	// Taken out: nothing of the group reaches noa any more, and dana and noa can't reach each other.
	if _, code := env.groupOp(t, dana, "removeFromGroup", g.ID, "noa"); code != "NOT_OWNER" {
		t.Fatalf("a member taking out another: %s", code)
	}
	if _, code := env.groupOp(t, hen, "leaveGroup", g.ID, ""); code != "OWNER_CANT_LEAVE" {
		t.Fatalf("the owner leaving: %s", code)
	}
	if after, code := env.groupOp(t, hen, "removeFromGroup", g.ID, "noa"); code != "" || strings.Join(after.Members, ",") != "hen,dana" {
		t.Fatalf("removeFromGroup: %+v %s", after, code)
	}
	noaSocket.envelopeOf(t, pb.Envelope_GROUP_CHANGED)
	if r := henSocket.groupSend(t, g.ID, map[string][]*phone{"dana": {dana}, "noa": {noa}}); r.Status != pb.SendResult_STALE_DEVICES {
		t.Fatalf("a group Send to a member taken out: %v", r)
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(noa)); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("to a former fellow member: %v", r)
	}
	if r := noaSocket.groupSend(t, g.ID, nil); r.Status != pb.SendResult_NOT_MEMBER {
		t.Fatalf("a group Send by a member taken out: %v", r)
	}
	if _, code := env.groupOp(t, noa, "leaveGroup", g.ID, ""); code != "NO_GROUP" {
		t.Fatalf("leaving a group taken out of: %s", code)
	}

	// dana leaves; then the owner deletes the group.
	if _, code := env.groupOp(t, dana, "leaveGroup", g.ID, ""); code != "" {
		t.Fatalf("leaveGroup: %s", code)
	}
	if _, code := env.groupOp(t, hen, "deleteGroup", g.ID, ""); code != "" {
		t.Fatalf("deleteGroup: %s", code)
	}
	if data, _ := env.groupCall(t, hen, `{ groups `+groupFields+` }`, nil); string(data) != "[]" {
		t.Fatalf("the owner's groups after deleting: %s", data)
	}
	if r := henSocket.groupSend(t, g.ID, nil); r.Status != pb.SendResult_NOT_MEMBER {
		t.Fatalf("a group Send to a deleted group: %v", r)
	}
}

// Removing a user takes it out of its groups and deletes the ones it owned, and both survive a restart of the file.
func TestARemovedUserLeavesItsGroups(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	hen, dana := env.phone(t, "hen"), env.phone(t, "dana")
	env.uploadKeys(t, hen, ecKey())
	env.uploadKeys(t, dana, ecKey())
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	owned := env.createGroup(t, hen)
	danas := env.createGroup(t, dana)
	env.groupOp(t, hen, "inviteToGroup", owned.ID, "dana")
	env.groupOp(t, dana, "acceptGroupInvite", owned.ID, "")
	env.groupOp(t, dana, "inviteToGroup", danas.ID, "hen")

	env.server.relay.Users.Remove("dana")
	env.server.relay.Revoked("dana")
	data, _ := env.groupCall(t, hen, `{ groups `+groupFields+` }`, nil)
	var list []groupAnswer
	json.Unmarshal(data, &list)
	if len(list) != 1 || list[0].ID != owned.ID || strings.Join(list[0].Members, ",") != "hen" {
		t.Fatalf("hen's groups after dana was removed: %s", data)
	}
	saved, _ := os.ReadFile(env.server.config.GroupsFile)
	if strings.Contains(string(saved), "dana") {
		t.Fatalf("groups.json still names dana: %s", saved)
	}
}
