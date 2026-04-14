// Package authz is used to authorize whether an identity has the required role.
package authz

import (
	"fmt"
	"slices"
	"strings"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/alis-exchange/auth/authn"
)

type Authorizer struct {
	identity *authn.Identity
	roles    []string
}

func New(identity *authn.Identity) *Authorizer {
	return &Authorizer{
		identity: identity,
		roles:    identity.Roles,
	}
}

func (a *Authorizer) HasRole(roles []string, onceOfPolicies ...*iampb.Policy) bool {
	allRoles := append(roles, a.rolesFromPolicies(onceOfPolicies...)...)
	for _, role := range allRoles {
		if slices.Contains(a.roles, role) {
			return true
		}
	}
	return false
}

func (a *Authorizer) AddRolesFromPolicies(policies ...*iampb.Policy) {
	a.roles = append(a.roles, a.rolesFromPolicies(policies...)...)
}

func (a *Authorizer) rolesFromPolicies(policies ...*iampb.Policy) []string {
	var roles []string
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, binding := range policy.Bindings {
			if binding == nil {
				continue
			}
			for _, memberText := range binding.Members {
				member := new(Member).parse(memberText)
				if resolver, ok := memberResolvers[member.Type]; ok {
					if resolver(a.identity, member) {
						roles = append(roles, binding.Role)
						break
					}
				}
			}
		}
	}
	return roles
}

type Member struct {
	Type string
	ID   string
}

func (m *Member) parse(text string) *Member {
	parts := strings.Split(text, ":")
	m.Type = parts[0]
	if len(parts) > 1 {
		m.ID = strings.Join(parts[1:], ":")
	}
	return m
}

var memberResolvers = map[string]func(identity *authn.Identity, member *Member) bool{
	"user": func(identity *authn.Identity, member *Member) bool {
		return identity.Type == authn.User && identity.ID == member.ID
	},
	"serviceAccount": func(identity *authn.Identity, member *Member) bool {
		return identity.Type == authn.ServiceAccount && identity.ID == member.ID
	},
	"domain": func(identity *authn.Identity, member *Member) bool {
		return strings.HasPrefix(identity.Email, "@"+member.ID)
	},
	"group": func(identity *authn.Identity, member *Member) bool {
		return slices.Contains(identity.GroupIDs, member.ID)
	},
}

func AddMemberResolver(memberTypes []string, resolver func(identity *authn.Identity, member *Member) bool) error {
	for _, memberType := range memberTypes {
		if _, ok := memberResolvers[memberType]; ok {
			return fmt.Errorf("resolver already registered for '%s'", memberType)
		}
		memberResolvers[memberType] = resolver
	}
	return nil
}
