package resolver

import (
	"context"
	"fmt"
	"log"
	"slices"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/recorder"
)

// callConversation checks call as callToken does and answers its room and the caller's view of its conversation.
func (r *Resolver) callConversation(ctx context.Context, call string, peer, group *string) (string, recorder.Conversation, error) {
	d, err := r.caller(ctx)
	if err != nil {
		return "", recorder.Conversation{}, err
	}
	if r.Recorder == nil {
		return "", recorder.Conversation{}, coded(CodeRecordingOff, "this server doesn't keep calls")
	}
	if !blobs.ValidID(call) {
		return "", recorder.Conversation{}, coded(pb.SendResult_INVALID.String(), "a call id is 32 lowercase hex digits")
	}
	room, status, detail := r.Relay.CallRoom(d, call, deref(peer), deref(group))
	if status != 0 {
		return "", recorder.Conversation{}, coded(status.String(), "%s", detail)
	}
	return room, recorder.Conversation{Owner: d.User, Peer: deref(peer), Group: deref(group)}, nil
}

// inCall checks call as callRecording does, and that the caller's device is in the call's LiveKit room now (when the
// server can ask LiveKit): only someone in a call may start or stop its recording. by is the device, user.device.
func (r *Resolver) inCall(ctx context.Context, call string, peer, group *string) (room string, conv recorder.Conversation, by string, err error) {
	room, conv, err = r.callConversation(ctx, call, peer, group)
	if err != nil {
		return "", conv, "", err
	}
	d, _ := r.caller(ctx) // callConversation checked it
	by = livekit.Identity(d.User, d.Number)
	if r.Relay.Live != nil {
		ids, err := r.Relay.Live.Participants(ctx, room)
		if err != nil {
			log.Printf("Call %s: listing its room: %v", call, err)
			return "", conv, "", fmt.Errorf("LiveKit isn't answering")
		}
		if !slices.Contains(ids, by) {
			return "", conv, "", coded(CodeNotInCall, "join the call before recording it")
		}
	}
	return room, conv, by, nil
}

// callRecording is call's saving as user sees it: the tracks user may read.
func (r *Resolver) callRecording(user, call string, s recorder.Status) *model.CallRecording {
	out := &model.CallRecording{Call: call, Recording: s.Recording, Tracks: []*model.RecordedTrack{}}
	if s.By != "" {
		out.By = &s.By
	}
	if !s.Started.IsZero() {
		started := s.Started.UTC()
		out.StartedAt = &started
	}
	for _, m := range r.Relay.Blobs.OfCall(call) {
		if !r.Relay.MayRead(user, m) {
			continue
		}
		if out.StartedAt == nil { // the saving ended before a restart: its tracks say when it began
			started := m.Track.Recording
			out.StartedAt = &started
		}
		out.Tracks = append(out.Tracks, &model.RecordedTrack{Blob: m.ID, Identity: m.Track.Identity,
			Kind: m.Track.Media, Codec: m.Track.Codec, StartedAt: m.Track.Started, RecordingStartedAt: m.Track.Recording,
			Size:     int(m.Size),
			Complete: m.Complete})
	}
	return out
}
