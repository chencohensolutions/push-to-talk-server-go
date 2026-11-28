package main

import (
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/relay"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// pairedForMedia is hen and dana, paired, with eli enrolled but no contact.
func pairedForMedia(t *testing.T, env *testEnv) (hen, dana, eli *phone) {
	t.Helper()
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli = env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	env.uploadKeys(t, hen, ecKey())
	env.uploadKeys(t, dana, ecKey())
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	return
}

// A shared original can be bigger than the old 100 MB limit (2026-11-28, hen: share videos), up to max_blob_mb.
func TestBlobOverTheOldLimit(t *testing.T) {
	env := newTestEnv(t)
	hen, _, _ := pairedForMedia(t, env)
	resp, _ := env.blobRequest(t, hen, http.MethodPut, burstID()+"?peer=dana&keep=media",
		map[string]string{relay.HeaderTotal: "5368709120"}, []byte("the first bytes"))
	if resp.StatusCode != 200 || resp.Header.Get(relay.HeaderOffset) != "15" {
		t.Fatalf("a 5 GB original: %d %v", resp.StatusCode, resp.Header)
	}
	over := int64(blobs.DefaultMaxFileBytes) + 1
	resp, _ = env.blobRequest(t, hen, http.MethodPut, burstID()+"?peer=dana",
		map[string]string{relay.HeaderTotal: strconv.FormatInt(over, 10)}, []byte("x"))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("over max_blob_mb: %d", resp.StatusCode)
	}
}

// An open file (a video's preview uploaded while the phone encodes it): no Blob-Total, readers follow it with
// ?follow=1 as it grows, and Blob-Last ends it. Without follow it is 409 until then. Its maker may DELETE it.
func TestBlobOpenFileIsFollowedAsItGrows(t *testing.T) {
	env := newTestEnv(t)
	hen, dana, eli := pairedForMedia(t, env)
	id := burstID()
	resp, _ := env.blobRequest(t, hen, http.MethodPut, id+"?peer=dana", map[string]string{relay.HeaderOpen: "true"}, []byte("part one|"))
	if resp.StatusCode != 200 || resp.Header.Get(relay.HeaderOpen) != "true" || resp.Header.Get(relay.HeaderComplete) != "false" {
		t.Fatalf("the first part: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := env.blobRequest(t, dana, http.MethodGet, id, nil, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("GET without follow while it grows: %d", resp.StatusCode)
	}

	// dana follows it; hen's next parts arrive in the same response.
	req, _ := http.NewRequest(http.MethodGet, env.public.URL+"/blob/"+id+"?follow=1", nil)
	got := make(chan []byte, 1)
	go func() {
		r, err := dana.client.Do(req)
		if err != nil {
			got <- nil
			return
		}
		defer r.Body.Close()
		data, _ := io.ReadAll(r.Body)
		got <- data
	}()
	time.Sleep(100 * time.Millisecond)
	env.blobRequest(t, hen, http.MethodPut, id, map[string]string{relay.HeaderOffset: "9"}, []byte("part two|"))
	resp, _ = env.blobRequest(t, hen, http.MethodPut, id, map[string]string{relay.HeaderOffset: "18", relay.HeaderLast: "true"}, []byte("the end"))
	if resp.StatusCode != 200 || resp.Header.Get(relay.HeaderComplete) != "true" || resp.Header.Get(relay.HeaderTotal) != "25" {
		t.Fatalf("the last part: %d %v", resp.StatusCode, resp.Header)
	}
	select {
	case data := <-got:
		if string(data) != "part one|part two|the end" {
			t.Fatalf("what the follower read: %q", data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the follower never finished")
	}
	if resp, data := env.blobRequest(t, dana, http.MethodGet, id, map[string]string{"Range": "bytes=9-"}, nil); resp.StatusCode != http.StatusPartialContent || string(data) != "part two|the end" {
		t.Fatalf("a range of the finished file: %d %q", resp.StatusCode, data)
	}

	// Only its maker deletes it.
	for _, p := range []*phone{dana, eli} {
		if resp, _ := env.blobRequest(t, p, http.MethodDelete, id, nil, nil); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("DELETE by %s: %d", p.user, resp.StatusCode)
		}
	}
	if resp, _ := env.blobRequest(t, hen, http.MethodDelete, id, nil, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE by its maker: %d", resp.StatusCode)
	}
	if resp, _ := env.blobRequest(t, dana, http.MethodGet, id, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET after DELETE: %d", resp.StatusCode)
	}
}

// A shared original (?keep=media) is kept media_days after it was uploaded (2026-11-28, hen: 30), other files
// blob_days; an upload left unfinished goes after 48 hours without a byte.
func TestSharedOriginalsAreKeptMediaDays(t *testing.T) {
	env := newTestEnv(t)
	hen, _, _ := pairedForMedia(t, env)
	original, preview, broken := burstID(), burstID(), burstID()
	env.blobRequest(t, hen, http.MethodPut, original+"?peer=dana&keep=media", map[string]string{relay.HeaderTotal: "8"}, []byte("original"))
	env.blobRequest(t, hen, http.MethodPut, preview+"?peer=dana", map[string]string{relay.HeaderTotal: "7"}, []byte("preview"))
	env.blobRequest(t, hen, http.MethodPut, broken+"?peer=dana", map[string]string{relay.HeaderTotal: "100"}, []byte("half"))
	if m, _ := env.relay.Blobs.Get(original); m.Keep != blobs.KeepMedia {
		t.Fatalf("?keep=media wasn't kept: %+v", m)
	}

	now := time.Now()
	sweep := func(daysOn, blobDays, mediaDays int) int {
		at := now.Add(time.Duration(daysOn) * 24 * time.Hour)
		return env.relay.Blobs.Expire(at.Add(-time.Duration(blobDays)*24*time.Hour), at.Add(-time.Duration(mediaDays)*24*time.Hour))
	}
	// An unfinished upload isn't swept while it is fresh.
	if n := sweep(0, 10, 30); n != 0 {
		t.Fatalf("at once: %d deleted", n)
	}
	// With blob_days 10 and media_days 30: twenty days on, the preview (and the unfinished upload) go and the
	// original stays.
	if n := sweep(20, 10, 30); n != 2 {
		t.Fatalf("twenty days on: %d deleted", n)
	}
	if _, ok := env.relay.Blobs.Get(preview); ok {
		t.Fatal("the preview outlived blob_days")
	}
	if _, ok := env.relay.Blobs.Get(original); !ok {
		t.Fatal("the original went before media_days")
	}
	// Thirty-one days on: the original goes.
	sweep(31, 10, 30)
	if _, ok := env.relay.Blobs.Get(original); ok {
		t.Fatal("the original outlived media_days")
	}
}

// A request for a shared original (2026-11-28): PUSH_MEDIA is high priority even with notifications off (the phone
// starts an upload), kept a day; push_user wakes only that user's devices.
func TestAMediaPushWakesOnlyPushUser(t *testing.T) {
	env, fcm := newPushEnv(t)
	_, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	env.registerPush(t, danaPhone, "dana-token", false)
	env.registerPush(t, henTablet, "tablet-token", true)
	env.closeSocket(t, danaSocket, danaPhone)
	env.closeSocket(t, tabletSocket, henTablet)

	send := &pb.Send{ClientId: "media", PushKind: pb.PushKind_PUSH_MEDIA, PushUser: "dana"}
	for _, d := range []store.Device{dev(danaPhone), dev(henTablet)} {
		send.Envelopes = append(send.Envelopes, &pb.Envelope{RecipientUser: d.User, RecipientDevice: uint32(d.Number),
			Type: pb.Envelope_MESSAGE, Ciphertext: []byte("ciphertext")})
	}
	henSocket.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	if r := henSocket.next(t, "send_result").GetSendResult(); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("send: %v", r)
	}
	m := fcm.next(t)
	if m.Token != "dana-token" || m.Data["kind"] != "media" || m.Android.Priority != "HIGH" || m.Android.TTL != "86400s" {
		t.Fatalf("dana's media push: %+v", m)
	}
	fcm.none(t, pushWindow+100*time.Millisecond) // hen's tablet isn't push_user: no push
}
