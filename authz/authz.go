// Package authz is used to authorize if an identity has access to do a certain action (possibly on a certain resource).
package authz

import (
	"fmt"
	"slices"
	"strings"

	"github.com/alis-exchange/auth/authn"
)

type MemberType string

const (
	User           MemberType = "user"
	ServiceAccount MemberType = "serviceAccount"
	Domain         MemberType = "domain"
	Group          MemberType = "group"
)

type Authorizer struct {
	identity *authn.Identity
	roles    []string
}

var memberResolvers = map[MemberType]func(identity *authn.Identity, memberType string, memberID string) bool{
	User: func(identity *authn.Identity, memberType, memberID string) bool {
		return identity.Type == authn.User && identity.ID == memberID
	},
	ServiceAccount: func(identity *authn.Identity, memberType, memberID string) bool {
		return identity.Type == authn.ServiceAccount && identity.ID == memberID
	},
	Domain: func(identity *authn.Identity, memberType, memberID string) bool {
		return strings.HasPrefix(identity.Email, "@"+memberID)
	},
	Group: func(identity *authn.Identity, memberType, memberID string) bool {
		return slices.Contains(identity.GroupIDs, memberID)
	},
}

func AddPolicyMemberResolver(memberTypes []string, resolver func(identity *authn.Identity, memberType string, memberID string) bool) error {
	for _, memberTypeString := range memberTypes {
		memberType := MemberType(memberTypeString)
		if memberType == User || memberType == ServiceAccount || memberType == Domain || memberType == Group {
			return fmt.Errorf("cannot register resolver for builtin type '%s'", memberType)
		}
		memberResolvers[memberType] = resolver
	}
	return nil
}
