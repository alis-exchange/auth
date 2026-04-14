// Package authz is used to authorize whether an identity has the required role.
package authz

import (
	"encoding/base64"
	"fmt"
	"slices"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/alis-exchange/auth/authn"
	"google.golang.org/protobuf/proto"
)

type Authorizer struct {
	identity *authn.Identity
	roles    []string
}

func New(identity *authn.Identity) (*Authorizer, error) {
	var roles []string

	// extract roles from iam policy if any
	if identity.Policy != "" {
		policyBytes, err := base64.StdEncoding.DecodeString(identity.Policy)
		if err != nil {
			return nil, fmt.Errorf("decoding identity iam policy: %w", err)
		}
		if len(policyBytes) > 0 {
			policy := &iampb.Policy{}
			err = proto.Unmarshal(policyBytes, policy)
			if err != nil {
				return nil, fmt.Errorf("unmarshalling identity iam policy: %w", err)
			}
			roles = rolesFromPolicies(identity, policy)
		}
	}

	// return authorizer
	return &Authorizer{
		identity: identity,
		roles:    roles,
	}, nil
}

func MustNew(identity *authn.Identity) *Authorizer {
	authorizer, err := New(identity)
	if err != nil {
		panic(err)
	}
	return authorizer
}

// HasRole returns true if the identity has one of the given roles in one of the
// given policies.
//
// If you want to re-use this authorizer in a scenario where the
// given policies are still relevant, rather use AddRolesFromPolicies to
// persit the policies in this authorizer. One example is doing an access control
// check in a List method, using some parent resource policies and then iterating
// over the database rows which are each individually checked whether the identity
// has access to them based on a policy in the row.
func (a *Authorizer) HasRole(roles []string, policies ...*iampb.Policy) bool {
	allRoles := append(a.roles, rolesFromPolicies(a.identity, policies...)...)
	for _, role := range roles {
		if slices.Contains(allRoles, role) {
			return true
		}
	}
	return false
}

// AddRolesFromPolicies adds roles that the identity has from the given policies.
//
// Rather provide the policies directly in HasRole if you plan on re-using this
// authorizer in a context where these policies are not applicable. One example
// is iterating over a list of database rows (each with their own policy), where
// one row's policy should not be considered in following row's access control.
func (a *Authorizer) AddRolesFromPolicies(policies ...*iampb.Policy) {
	a.AddRoles(rolesFromPolicies(a.identity, policies...)...)
}

// AddRoles adds roles that the identity has.
func (a *Authorizer) AddRoles(roles ...string) {
	a.roles = append(a.roles, roles...)
}

func rolesFromPolicies(identity *authn.Identity, policies ...*iampb.Policy) []string {
	var roles []string
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, binding := range policy.Bindings {
			if isMember(identity, binding.GetMembers()) {
				roles = append(roles, binding.Role)
			}
		}
	}
	return roles
}
