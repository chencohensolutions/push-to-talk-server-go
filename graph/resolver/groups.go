package resolver

import (
	"errors"

	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/groups"
)

func groupModel(g groups.Group) *model.Group {
	return &model.Group{ID: g.ID, Owner: g.Owner, Members: append([]string{}, g.Members...),
		Invited: append([]string{}, g.Invited...), CreatedAt: g.Created}
}

// groupError is an error of package groups as a GraphQL error with its code.
func groupError(err error) error {
	codes := map[error]string{
		groups.ErrNoGroup:    CodeNoGroup,
		groups.ErrNotOwner:   CodeNotOwner,
		groups.ErrNotMember:  CodeNotMember,
		groups.ErrNotInvited: CodeNotInvited,
		groups.ErrOwnerLeave: CodeOwnerCantLeave,
		groups.ErrFull:       CodeGroupFull,
		groups.ErrTooMany:    CodeTooManyGroups,
	}
	for e, code := range codes {
		if errors.Is(err, e) {
			return coded(code, "%v", e)
		}
	}
	return err
}

// visibleGroup is group id when user is in it (a member or invited); NO_GROUP otherwise, so ids of other groups
// can't be probed.
func (r *Resolver) visibleGroup(id, user string) (groups.Group, error) {
	g, ok := r.Relay.Groups.Get(id)
	if !ok || (!g.Member(user) && !g.IsInvited(user)) {
		return groups.Group{}, groupError(groups.ErrNoGroup)
	}
	return g, nil
}
