package basil

import (
	"context"
	"errors"
	"io"

	"github.com/openbasil/basil-go/internal/pb"
)

// CatalogKind classifies a catalog entry returned by [Client.ListCatalog]. It
// mirrors basil.broker.v1.CatalogKind.
type CatalogKind int32

const (
	// CatalogKindUnspecified is the zero value.
	CatalogKindUnspecified CatalogKind = 0
	// CatalogKindSigning is an asymmetric signing key.
	CatalogKindSigning CatalogKind = 1
	// CatalogKindValue is an opaque secret value.
	CatalogKindValue CatalogKind = 2
	// CatalogKindEncryption is a symmetric AEAD encryption key.
	CatalogKindEncryption CatalogKind = 3
)

// String returns the broker's enum name for the catalog kind.
func (k CatalogKind) String() string { return pb.CatalogKind(k).String() }

// Secret is a fetched secret payload and the version it was read from, as
// returned by [Client.GetSecret].
type Secret struct {
	// Value is the raw secret bytes.
	Value []byte
	// Version is the version these bytes were read from.
	Version uint32
}

// CatalogEntry is one entry visible to the caller, as returned by
// [Client.ListCatalog].
type CatalogEntry struct {
	// Name is the dotted catalog name.
	Name string
	// Kind is the entry class (signing key, value, or encryption key).
	Kind CatalogKind
	// KeyType is the key's type for signing/encryption keys; nil for opaque
	// values.
	KeyType *KeyType
	// LatestVersion is the latest version visible to the caller.
	LatestVersion uint32
}

// GetSecret fetches the secret named secretID. Pass a non-nil version to read a
// specific version; nil selects the latest visible version.
func (c *Client) GetSecret(ctx context.Context, secretID string, version *uint32) (*Secret, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.secret.GetSecret(ctx, &pb.GetSecretRequest{
		SecretId: secretID,
		Version:  version,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &Secret{Value: resp.GetValue(), Version: resp.GetVersion()}, nil
}

// SetSecret stores value under the secret named secretID, creating a new
// version, and returns that version number.
func (c *Client) SetSecret(ctx context.Context, secretID string, value []byte) (uint32, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.secret.SetSecret(ctx, &pb.SetSecretRequest{
		SecretId: secretID,
		Value:    value,
	})
	if err != nil {
		return 0, statusError(err)
	}
	return resp.GetVersion(), nil
}

// RotateSecret rotates the secret named secretID to a new version and returns
// that version number.
func (c *Client) RotateSecret(ctx context.Context, secretID string) (uint32, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.secret.RotateSecret(ctx, &pb.RotateSecretRequest{SecretId: secretID})
	if err != nil {
		return 0, statusError(err)
	}
	return resp.GetVersion(), nil
}

// ListCatalog returns the catalog entries visible to the caller, draining the
// broker's server stream into a slice. Pass a non-nil prefix to filter by a
// dotted-name prefix; nil returns all visible entries.
func (c *Client) ListCatalog(ctx context.Context, prefix *string) ([]CatalogEntry, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	stream, err := c.secret.ListCatalog(ctx, &pb.ListCatalogRequest{Prefix: prefix})
	if err != nil {
		return nil, statusError(err)
	}
	var entries []CatalogEntry
	for {
		e, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return entries, nil
		}
		if err != nil {
			return nil, statusError(err)
		}
		entries = append(entries, catalogEntryFromProto(e))
	}
}

func catalogEntryFromProto(e *pb.CatalogEntry) CatalogEntry {
	out := CatalogEntry{
		Name:          e.GetName(),
		Kind:          CatalogKind(e.GetKind()),
		LatestVersion: e.GetLatestVersion(),
	}
	if e.KeyType != nil {
		kt := keyTypeFromProto(e.GetKeyType())
		out.KeyType = &kt
	}
	return out
}
