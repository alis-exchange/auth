package authn

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

func expect[T comparable](t *testing.T, got, expected T) {
	if got != expected {
		t.Fatalf("got %v, expected %v", got, expected)
	}
}

func expectSlice[T comparable](t *testing.T, got, expected []T) {
	if len(got) != len(expected) {
		t.Fatalf("got %v, expected %v", got, expected)
	}
	for i := range got {
		if got[i] != expected[i] {
			t.Fatalf("got %v, expected %v", got, expected)
		}
	}
}

var testIdentity = &Identity{
	Type:     User,
	ID:       "1934872948",
	Email:    "john@example.com",
	Roles:    []string{"roles/admin"},
	GroupIDs: []string{"df913r888"},
}

func TestContext(t *testing.T) {
	ctx := testIdentity.Context(t.Context())
	identity := MustFromContext(ctx)
	expect(t, identity.Type, testIdentity.Type)
	expect(t, identity.ID, testIdentity.ID)
	expect(t, identity.Email, testIdentity.Email)
	expectSlice(t, identity.Roles, testIdentity.Roles)
	expectSlice(t, identity.GroupIDs, testIdentity.GroupIDs)
}

func TestMarshal(t *testing.T) {
	data := testIdentity.Marshal()
	identity := MustUnmarshal(data)
	expect(t, identity.Type, testIdentity.Type)
	expect(t, identity.ID, testIdentity.ID)
	expect(t, identity.Email, testIdentity.Email)
	expectSlice(t, identity.Roles, testIdentity.Roles)
	expectSlice(t, identity.GroupIDs, testIdentity.GroupIDs)
}

func TestMetadata(t *testing.T) {
	ctx := testIdentity.OutgoingMetadata(t.Context())
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("outgoing metadata not found")
	}
	ctx = metadata.NewIncomingContext(t.Context(), md)
	identity := MustFromIncomingMetadata(ctx)
	expect(t, identity.Type, testIdentity.Type)
	expect(t, identity.ID, testIdentity.ID)
	expect(t, identity.Email, testIdentity.Email)
	expectSlice(t, identity.Roles, testIdentity.Roles)
	expectSlice(t, identity.GroupIDs, testIdentity.GroupIDs)
}
