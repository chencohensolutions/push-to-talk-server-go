package resolver

import (
	"context"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
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

// callRecording is call's saving as user sees it: the tracks user may read.
func (r *Resolver) callRecording(user, call string, s recorder.Status) *model.CallRecording {
	out := &model.CallRecording{Call: call, Recording: s.Recording, Tracks: []*model.RecordedTrack{}}
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
