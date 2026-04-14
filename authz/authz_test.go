package authz

import (
	"testing"

	"cloud.google.com/go/iam/apiv1/iampb"
	"github.com/alis-exchange/auth/authn"
)

var testIdentity = &authn.Identity{
	Type:     authn.User,
	ID:       "1934872948",
	Email:    "john@example.com",
	Roles:    []string{"roles/viewer"},
	GroupIDs: []string{"df913r888"},
}

func TestHasRoleFromIdentity(t *testing.T) {
	testAZ := New(testIdentity)
	if !testAZ.HasRole([]string{"roles/admin", "roles/editor", "roles/viewer"}) {
		t.Fatal("expected to have role 'roles/viewer'")
	}
	if testAZ.HasRole([]string{"roles/admin", "roles/editor"}) {
		t.Fatal("expected not to have role 'roles/admin' or 'roles/editor'")
	}
}

func TestHasRoleFromPolicy(t *testing.T) {
	testAZ := New(testIdentity)
	testAZ.AddRolesFromPolicies(&iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role: "roles/admin",
				Members: []string{
					"user:12345678",
					"serviceAccount:alis-build@my-project.iam.gserviceaccount.com",
				},
			},
			{
				Role: "roles/editor",
				Members: []string{
					"serviceAccount:alis-build@my-project.iam.gserviceaccount.com",
					"user:" + testIdentity.ID,
				},
			},
		},
	})
	if testAZ.HasRole([]string{"roles/admin"}) {
		t.Fatal("expected not to have role 'roles/admin'")
	}
	if !testAZ.HasRole([]string{"roles/editor"}) {
		t.Fatal("expected to have role 'roles/editor'")
	}
}

func TestHasRoleFromOnceOffPolicy(t *testing.T) {
	testAZ := New(testIdentity)
	onceOffPolicy := &iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role: "roles/admin",
				Members: []string{
					"user:12345678",
					"serviceAccount:alis-build@my-project.iam.gserviceaccount.com",
				},
			},
			{
				Role: "roles/editor",
				Members: []string{
					"serviceAccount:alis-build@my-project.iam.gserviceaccount.com",
					"user:" + testIdentity.ID,
				},
			},
		},
	}
	if !testAZ.HasRole([]string{"roles/editor"}, onceOffPolicy) {
		t.Fatal("expected to have role 'roles/editor'")
	}
	if testAZ.HasRole([]string{"roles/editor"}) {
		t.Fatal("expected not to have role 'roles/editor'")
	}
}

func TestMemberResolvers(t *testing.T) {
	AddMemberResolver([]string{"account"}, func(identity *authn.Identity, member *Member) bool {
		switch member.ID {
		case "abc":
			return true
		}
		return false
	})
	testAZ := New(testIdentity)
	if !testAZ.HasRole([]string{"roles/admin"}, &iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role: "roles/admin",
				Members: []string{
					"account:abc",
				},
			},
		},
	}) {
		t.Fatal("expected to have role 'roles/admin'")
	}
	if testAZ.HasRole([]string{"roles/admin"}, &iampb.Policy{
		Bindings: []*iampb.Binding{
			{
				Role: "roles/admin",
				Members: []string{
					"account:def",
				},
			},
		},
	}) {
		t.Fatal("expected not to have role 'roles/admin'")
	}
}
