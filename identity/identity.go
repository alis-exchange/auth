// Package identity provides the base identity structure that authn and authz work with.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/metadata"
)

const (
	User           Type   = "user"
	ServiceAccount Type   = "serviceAccount"
	IdentityCtxKey CtxKey = "identity"
)

type (
	Type     string
	CtxKey   string
	Identity struct {
		Type     Type
		ID       string   // E.g. "1934872948" or "alis-build@my-project.iam.gserviceaccount.com"
		Email    string   // E.g. "john@example.com" or "alis-build@myproject.iam.gserviceaccount.com"
		Roles    []string // Optional environment level roles that the user has, e.g. roles/admin.
		GroupIDs []string // Optional groups that the user is part of.
	}
)

// PolicyMember returns the member to use in iam policy bindings.
// E.g. "user:1234129384" or "serviceAccount:alis-build@myproject.iam.gserviceaccount.com"
func (i *Identity) PolicyMember() string {
	return string(i.Type) + ":" + i.ID
}

// Context returns a derived context with the identity value in it to use locally.
// Use OutgoingMetadata if you want remote services to identify the requester.
// You can use Context and OutgoingMetadata together.
func (i *Identity) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, IdentityCtxKey, i)
}

// FromContext returns the Identity inside the given ctx, if any.
func FromContext(ctx context.Context) (*Identity, error) {
	ctxValue := ctx.Value(IdentityCtxKey)
	if ctxValue == nil {
		return nil, errors.New("no Identity found in ctx")
	}
	identity, ok := ctxValue.(*Identity)
	if !ok || identity == nil {
		return nil, errors.New("no Identity found in ctx")
	}
	return identity, nil
}

// MustFromContext does the same as FromContext, but panics on an error.
func MustFromContext(ctx context.Context) *Identity {
	identity, err := FromContext(ctx)
	if err != nil {
		panic(fmt.Sprintf("identity.MustFromContext: %v", err))
	}
	return identity
}

// Marshal returns the bytes representation of the identity.
func (i *Identity) Marshal() []byte {
	if i == nil {
		return nil
	}
	data, err := json.Marshal(i)
	if err != nil {
		panic(err) // impossible
	}
	return data
}

// Unmarshal returns the identity represented by the bytes.
func Unmarshal(data []byte) (*Identity, error) {
	var identity Identity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, err
	}
	return &identity, nil
}

// MustUnmarshal does the same as [Unmarshal], but panics on an error.
func MustUnmarshal(data []byte) *Identity {
	identity, err := Unmarshal(data)
	if err != nil {
		panic(fmt.Sprintf("identity.MustUnmarshal: %v", err))
	}
	return identity
}

// OutgoingMetadata returns a derived context with the identity value in it.
// Enables downstream gRPC services in the same environment to identify the requester.
func (i *Identity) OutgoingMetadata(ctx context.Context) context.Context {
	if i == nil {
		return ctx
	}
	value := string(i.Marshal())
	return metadata.AppendToOutgoingContext(ctx, "identity", value)
}

// FromIncomingMetadata returns the Identity inside the given gRPC context, if any.
func FromIncomingMetadata(ctx context.Context) (*Identity, error) {
	values := metadata.ValueFromIncomingContext(ctx, "identity")
	if len(values) == 0 {
		return nil, errors.New("no identity value found in incoming metadata")
	}
	data := []byte(values[len(values)-1]) // use last appended value
	identity, err := Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling incoming metadata: %v", err)
	}
	return identity, nil
}

// MustFromIncomingMetadata does the same as FromIncomingMetadata, but panics on an error.
func MustFromIncomingMetadata(ctx context.Context) *Identity {
	identity, err := FromIncomingMetadata(ctx)
	if err != nil {
		panic(fmt.Sprintf("identity.MustFromIncomingMetadata: %v", err))
	}
	return identity
}
