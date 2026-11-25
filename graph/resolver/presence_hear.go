package resolver

import (
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
)

// hearModel is a can-hear state as the schema's Hear (nil when not said, or hidden).
func hearModel(h pb.Hear) *model.Hear {
	var m model.Hear
	switch h {
	case pb.Hear_HEAR_OK:
		m = model.HearOk
	case pb.Hear_HEAR_SILENT:
		m = model.HearSilent
	case pb.Hear_HEAR_DND:
		m = model.HearDnd
	case pb.Hear_HEAR_IN_CALL:
		m = model.HearInCall
	default:
		return nil
	}
	return &m
}
