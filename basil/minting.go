package basil

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NatsJwtType asserts the NATS claim shape for [Client.SignNatsJwt]. It mirrors
// basil.broker.v1.NatsJwtType; the zero value derives the type from
// claims.nats.type.
type NatsJwtType int32

const (
	// NatsJwtTypeUnspecified makes no caller assertion (derive from claims).
	NatsJwtTypeUnspecified NatsJwtType = 0
	// NatsJwtTypeUser asserts nats.type=user.
	NatsJwtTypeUser NatsJwtType = 1
	// NatsJwtTypeAccount asserts nats.type=account.
	NatsJwtTypeAccount NatsJwtType = 2
	// NatsJwtTypeOperator asserts nats.type=operator.
	NatsJwtTypeOperator NatsJwtType = 3
	// NatsJwtTypeSigner asserts nats.type=signer.
	NatsJwtTypeSigner NatsJwtType = 4
	// NatsJwtTypeServer asserts nats.type=server.
	NatsJwtTypeServer NatsJwtType = 5
	// NatsJwtTypeCurve asserts nats.type=curve.
	NatsJwtTypeCurve NatsJwtType = 6
)

// String returns the broker's enum name for the NATS JWT type.
func (t NatsJwtType) String() string { return pb.NatsJwtType(t).String() }

// NatsJtiMode controls how [Client.SignNatsJwt] handles a supplied but
// incorrect NATS jti. It mirrors basil.broker.v1.NatsJtiMode.
type NatsJtiMode int32

const (
	// NatsJtiModeRequireValid inserts a missing jti but rejects a supplied
	// value that does not match the NATS standard-claim hash. This is the zero
	// value.
	NatsJtiModeRequireValid NatsJtiMode = 0
	// NatsJtiModeRewrite inserts or replaces jti with the computed NATS
	// standard-claim hash.
	NatsJtiModeRewrite NatsJtiMode = 1
)

// String returns the broker's enum name for the jti mode.
func (m NatsJtiMode) String() string { return pb.NatsJtiMode(m).String() }

// NatsJwtValidationReason explains a [NatsJwtValidation] decision.
type NatsJwtValidationReason int32

const (
	// NatsJwtValidationReasonUnknown means the broker returned an unset or
	// unknown future reason.
	NatsJwtValidationReasonUnknown NatsJwtValidationReason = 0
	// NatsJwtValidationReasonValid means the token is valid under the supplied
	// candidate signer set.
	NatsJwtValidationReasonValid NatsJwtValidationReason = 1
	// NatsJwtValidationReasonMalformed means compact JWT syntax, header,
	// claims, issuer, or signature encoding is malformed.
	NatsJwtValidationReasonMalformed NatsJwtValidationReason = 2
	// NatsJwtValidationReasonBadSignature means the signer matched, but the
	// Ed25519 signature is invalid.
	NatsJwtValidationReasonBadSignature NatsJwtValidationReason = 3
	// NatsJwtValidationReasonUnknownSigner means no supplied candidate signer
	// matched the token's embedded iss.
	NatsJwtValidationReasonUnknownSigner NatsJwtValidationReason = 4
	// NatsJwtValidationReasonExpired means the token is expired.
	NatsJwtValidationReasonExpired NatsJwtValidationReason = 5
	// NatsJwtValidationReasonNotYetValid means the token's nbf is in the future.
	NatsJwtValidationReasonNotYetValid NatsJwtValidationReason = 6
	// NatsJwtValidationReasonWrongType means the token's nats.type does not
	// match the caller assertion.
	NatsJwtValidationReasonWrongType NatsJwtValidationReason = 7
)

// String returns the broker's enum name for the validation reason.
func (r NatsJwtValidationReason) String() string {
	return pb.NatsJwtValidationReason(r).String()
}

// Credential is a minted credential (a JWT or NATS token) and its expiry, as
// returned by the minting methods.
type Credential struct {
	// Token is the compact token (a JWT, NATS JWT, or NATS creds token).
	Token string
	// ExpiresAt is the absolute expiry, or the zero time when the credential
	// does not expire.
	ExpiresAt time.Time
}

// JwtRequest is the input to [Client.MintJwt].
type JwtRequest struct {
	// KeyID is the catalog name of the signing key.
	KeyID string
	// Subject sets the JWT sub claim; empty omits it (the generic minter
	// requires a subject, so set it).
	Subject string
	// TTL sets exp relative to issue time; zero mints a non-expiring token.
	TTL time.Duration
	// Claims are additional, non-reserved claims to embed. They may be a
	// JSON-marshaled map/struct, json.RawMessage, []byte, or string containing a
	// JSON object. When decoding claim JSON into maps, use
	// json.Decoder.UseNumber so large integers are not converted to float64
	// before Basil sees them.
	Claims any
}

// NatsUserRequest is the input to [Client.MintNatsUser].
type NatsUserRequest struct {
	// KeyID is the catalog name of the issuing account signing key.
	KeyID string
	// SubjectUserNKey is the subject user public NKey (U…).
	SubjectUserNKey string
	// Name is the human-readable user name (the name claim).
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
	// PubAllow lists subjects the user may publish to (empty = unrestricted).
	PubAllow []string
	// PubDeny lists subjects the user may not publish to.
	PubDeny []string
	// SubAllow lists subjects the user may subscribe to (empty = unrestricted).
	SubAllow []string
	// SubDeny lists subjects the user may not subscribe to.
	SubDeny []string
	// IssuerAccount names the owning account identity, required when KeyID is
	// an account signing key rather than the account identity itself. It
	// populates the minted user JWT's nats.issuer_account claim; empty omits it.
	IssuerAccount string
}

// NatsAccountRequest is the input to [Client.MintNatsAccount].
type NatsAccountRequest struct {
	// KeyID is the catalog name of the issuing operator signing key.
	KeyID string
	// SubjectAccountNKey is the subject account public NKey (A…).
	SubjectAccountNKey string
	// Name is the human-readable account name.
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
	// SigningKeys are account signing keys (A…) authorized to sign on the
	// account's behalf.
	SigningKeys []string
}

// NatsOperatorRequest is the input to [Client.MintNatsOperator].
type NatsOperatorRequest struct {
	// KeyID is the catalog name of the issuing operator signing key.
	KeyID string
	// SubjectOperatorNKey is the subject operator public NKey (O…); empty
	// self-signs (sub == iss).
	SubjectOperatorNKey string
	// Name is the human-readable operator name.
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
	// SigningKeys are operator signing keys (O…).
	SigningKeys []string
	// AccountServerURL is the account-resolver / account-server URL; empty
	// omits it.
	AccountServerURL string
	// SystemAccount is the system account public NKey (A…); empty omits it.
	SystemAccount string
}

// NatsSignerRequest is the input to [Client.MintNatsSigner].
type NatsSignerRequest struct {
	// KeyID is the catalog name of the issuing account or operator signing key.
	KeyID string
	// SubjectNKey is the subject signing-key public NKey; it shares the
	// issuer's role.
	SubjectNKey string
	// Name is the human-readable name.
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
}

// NatsServerRequest is the input to [Client.MintNatsServer].
type NatsServerRequest struct {
	// KeyID is the catalog name of the issuing signing key.
	KeyID string
	// SubjectServerNKey is the subject server public NKey (N…).
	SubjectServerNKey string
	// Name is the human-readable server name.
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
}

// NatsCurveRequest is the input to [Client.MintNatsCurve].
type NatsCurveRequest struct {
	// KeyID is the catalog name of the issuing signing key.
	KeyID string
	// SubjectCurveNKey is the subject curve public NKey (X…).
	SubjectCurveNKey string
	// Name is the human-readable name.
	Name string
	// TTL is the lifetime; zero mints a non-expiring token.
	TTL time.Duration
}

// NatsCurveEncryptRequest is the input to [Client.EncryptNatsCurve].
type NatsCurveEncryptRequest struct {
	// KeyID is the catalog name of the custodied sender xkey.
	KeyID string
	// RecipientPublicXKey is the recipient public NATS curve key (X...).
	RecipientPublicXKey string
	// Plaintext is the payload to encrypt.
	Plaintext []byte
}

// NatsCurveDecryptRequest is the input to [Client.DecryptNatsCurve].
type NatsCurveDecryptRequest struct {
	// KeyID is the catalog name of the custodied recipient xkey.
	KeyID string
	// SenderPublicXKey is the sender public NATS curve key (X...).
	SenderPublicXKey string
	// Ciphertext is the xkv1 NATS xkey box.
	Ciphertext []byte
}

// NatsJwtRequest is the input to [Client.SignNatsJwt]. The broker derives iss
// from the signing key, validates sub and nats.type, computes the NATS jti, and
// signs with the ed25519-nkey NATS JWS profile.
type NatsJwtRequest struct {
	// KeyID is the catalog name of the NATS signing key.
	KeyID string
	// Claims is the full NATS JWT claims object; it must contain sub and nats;
	// name is optional. It may be a JSON-marshaled map/struct, json.RawMessage,
	// []byte, or string containing a JSON object. When decoding claim JSON into
	// maps, use json.Decoder.UseNumber so large integers are not converted to
	// float64 before Basil sees them.
	Claims any
	// ExpectedType optionally asserts against claims.nats.type.
	ExpectedType NatsJwtType
	// TTL is a relative lifetime; mutually exclusive with ExpiresAt. Zero omits
	// it.
	TTL time.Duration
	// ExpiresAt is an absolute expiry; mutually exclusive with TTL. The zero
	// time omits it.
	ExpiresAt time.Time
	// IssuedAt sets iat; the zero time lets the broker use its own time unless
	// claims already carry iat.
	IssuedAt time.Time
	// JtiMode selects whether to reject or rewrite a mismatched supplied jti.
	JtiMode NatsJtiMode
}

// AllowedSigner is one candidate signer to trust when validating a presented
// NATS JWT. Construct one with [AllowedSignerKeyID] or
// [AllowedSignerNatsPublicKey].
type AllowedSigner struct {
	keyID         string
	natsPublicKey string
}

// AllowedSignerKeyID trusts a signer by catalog key name. The broker resolves
// the key's public NKey and authorizes access to that catalog entry.
func AllowedSignerKeyID(keyID string) AllowedSigner {
	return AllowedSigner{keyID: keyID}
}

// AllowedSignerNatsPublicKey trusts a signer by raw public NKey (U..., A...,
// O..., etc.).
func AllowedSignerNatsPublicKey(publicKey string) AllowedSigner {
	return AllowedSigner{natsPublicKey: publicKey}
}

// ValidateNatsJwtRequest is the input to [NatsClient.ValidateNatsJwt].
type ValidateNatsJwtRequest struct {
	// JWT is the compact NATS JWT to validate.
	JWT string
	// AllowedSigners is the non-empty candidate trust-root set.
	AllowedSigners []AllowedSigner
	// ExpectedType optionally asserts against claims.nats.type.
	ExpectedType NatsJwtType
}

// NatsJwtValidation is the parsed validation result for a presented NATS JWT.
type NatsJwtValidation struct {
	// Valid is true only when Reason is NatsJwtValidationReasonValid.
	Valid bool
	// Reason is the machine-readable validation result.
	Reason NatsJwtValidationReason
	// Subject is the extracted sub, when the token was parseable.
	Subject string
	// Issuer is the extracted iss, when the token was parseable.
	Issuer string
	// MatchedSignerKeyID is set when the matching candidate was a catalog key.
	MatchedSignerKeyID string
	// JWTType is the extracted nats.type.
	JWTType NatsJwtType
	// ExpiresAt is the extracted exp, or the zero time when absent.
	ExpiresAt time.Time
	// IssuedAt is the extracted iat, or the zero time when absent.
	IssuedAt time.Time
}

// CertificateRequest is the input to [Client.IssueCertificate].
type CertificateRequest struct {
	// IssuerKeyID is the catalog name of the issuing CA key (a pki issue role).
	IssuerKeyID string
	// CommonName is the certificate common name.
	CommonName string
	// DNSSANs are DNS subject alternative names.
	DNSSANs []string
	// IPSANs are IP subject alternative names.
	IPSANs []string
	// TTL is the certificate lifetime; zero lets the issuing role's default
	// apply.
	TTL time.Duration
}

// Certificate is an issued X.509 leaf, its private key, and its trust chain, as
// returned by [Client.IssueCertificate]. Unlike every other broker operation
// this releases private key material to the caller: a TLS server needs the leaf
// private key to terminate connections.
type Certificate struct {
	// CertChainDER is the DER leaf certificate followed by any issuer
	// certificates.
	CertChainDER [][]byte
	// PrivateKeyDER is the DER PKCS#8 leaf private key (released to the caller).
	PrivateKeyDER []byte
	// CAChainDER is the DER issuing-CA / trust-bundle certificates.
	CAChainDER [][]byte
}

// NatsClient exposes the broker's NatsService operations.
type NatsClient struct {
	c *Client
}

// Nats returns the NatsService sub-client.
func (c *Client) Nats() NatsClient {
	return NatsClient{c: c}
}

// MintJwt mints a generic JWT with caller-supplied claims, signed in place by
// the catalog key named req.KeyID.
func (c *Client) MintJwt(ctx context.Context, req JwtRequest) (*Credential, error) {
	claimsJSON, err := optionalObjectJSON(req.Claims, "jwt claims")
	if err != nil {
		return nil, err
	}
	pbReq := &pb.MintJwtRequest{
		KeyId:           req.KeyID,
		Ttl:             durationOrNil(req.TTL),
		ExtraClaimsJson: claimsJSON,
	}
	if req.Subject != "" {
		pbReq.Subject = &req.Subject
	}
	return c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return c.minting.MintJwt(ctx, pbReq)
	})
}

// MintNatsUser mints a NATS user JWT signed by the account key named req.KeyID.
func (c *Client) MintNatsUser(ctx context.Context, req NatsUserRequest) (*Credential, error) {
	return c.Nats().MintNatsUser(ctx, req)
}

// MintNatsUser mints a NATS user JWT signed by the account key named req.KeyID.
func (n NatsClient) MintNatsUser(ctx context.Context, req NatsUserRequest) (*Credential, error) {
	pbReq := &pb.MintNatsUserRequest{
		KeyId:           req.KeyID,
		SubjectUserNkey: req.SubjectUserNKey,
		Name:            req.Name,
		Ttl:             durationOrNil(req.TTL),
		PubAllow:        req.PubAllow,
		PubDeny:         req.PubDeny,
		SubAllow:        req.SubAllow,
		SubDeny:         req.SubDeny,
	}
	if req.IssuerAccount != "" {
		pbReq.IssuerAccount = &req.IssuerAccount
	}
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsUser(ctx, pbReq)
	})
}

// MintNatsAccount mints a NATS account JWT signed by the operator key named
// req.KeyID.
func (c *Client) MintNatsAccount(ctx context.Context, req NatsAccountRequest) (*Credential, error) {
	return c.Nats().MintNatsAccount(ctx, req)
}

// MintNatsAccount mints a NATS account JWT signed by the operator key named
// req.KeyID.
func (n NatsClient) MintNatsAccount(ctx context.Context, req NatsAccountRequest) (*Credential, error) {
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsAccount(ctx, &pb.MintNatsAccountRequest{
			KeyId:              req.KeyID,
			SubjectAccountNkey: req.SubjectAccountNKey,
			Name:               req.Name,
			Ttl:                durationOrNil(req.TTL),
			SigningKeys:        req.SigningKeys,
		})
	})
}

// MintNatsOperator mints a NATS operator JWT (usually self-signed) with the key
// named req.KeyID.
func (c *Client) MintNatsOperator(ctx context.Context, req NatsOperatorRequest) (*Credential, error) {
	return c.Nats().MintNatsOperator(ctx, req)
}

// MintNatsOperator mints a NATS operator JWT (usually self-signed) with the key
// named req.KeyID.
func (n NatsClient) MintNatsOperator(ctx context.Context, req NatsOperatorRequest) (*Credential, error) {
	pbReq := &pb.MintNatsOperatorRequest{
		KeyId:       req.KeyID,
		Name:        req.Name,
		Ttl:         durationOrNil(req.TTL),
		SigningKeys: req.SigningKeys,
	}
	if req.SubjectOperatorNKey != "" {
		pbReq.SubjectOperatorNkey = &req.SubjectOperatorNKey
	}
	if req.AccountServerURL != "" {
		pbReq.AccountServerUrl = &req.AccountServerURL
	}
	if req.SystemAccount != "" {
		pbReq.SystemAccount = &req.SystemAccount
	}
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsOperator(ctx, pbReq)
	})
}

// MintNatsSigner mints a NATS account/operator signing-key JWT with the key
// named req.KeyID.
func (c *Client) MintNatsSigner(ctx context.Context, req NatsSignerRequest) (*Credential, error) {
	return c.Nats().MintNatsSigner(ctx, req)
}

// MintNatsSigner mints a NATS account/operator signing-key JWT with the key
// named req.KeyID.
func (n NatsClient) MintNatsSigner(ctx context.Context, req NatsSignerRequest) (*Credential, error) {
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsSigner(ctx, &pb.MintNatsSignerRequest{
			KeyId:       req.KeyID,
			SubjectNkey: req.SubjectNKey,
			Name:        req.Name,
			Ttl:         durationOrNil(req.TTL),
		})
	})
}

// MintNatsServer mints a NATS server JWT with the key named req.KeyID.
func (c *Client) MintNatsServer(ctx context.Context, req NatsServerRequest) (*Credential, error) {
	return c.Nats().MintNatsServer(ctx, req)
}

// MintNatsServer mints a NATS server JWT with the key named req.KeyID.
func (n NatsClient) MintNatsServer(ctx context.Context, req NatsServerRequest) (*Credential, error) {
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsServer(ctx, &pb.MintNatsServerRequest{
			KeyId:             req.KeyID,
			SubjectServerNkey: req.SubjectServerNKey,
			Name:              req.Name,
			Ttl:               durationOrNil(req.TTL),
		})
	})
}

// MintNatsCurve mints a NATS curve (x25519 xkey) JWT with the key named
// req.KeyID.
func (c *Client) MintNatsCurve(ctx context.Context, req NatsCurveRequest) (*Credential, error) {
	return c.Nats().MintNatsCurve(ctx, req)
}

// MintNatsCurve mints a NATS curve (x25519 xkey) JWT with the key named
// req.KeyID.
func (n NatsClient) MintNatsCurve(ctx context.Context, req NatsCurveRequest) (*Credential, error) {
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.MintNatsCurve(ctx, &pb.MintNatsCurveRequest{
			KeyId:            req.KeyID,
			SubjectCurveNkey: req.SubjectCurveNKey,
			Name:             req.Name,
			Ttl:              durationOrNil(req.TTL),
		})
	})
}

// EncryptNatsCurve encrypts req.Plaintext with the custodied NATS curve xkey
// named req.KeyID to req.RecipientPublicXKey.
func (c *Client) EncryptNatsCurve(ctx context.Context, req NatsCurveEncryptRequest) ([]byte, error) {
	return c.Nats().EncryptNatsCurve(ctx, req)
}

// EncryptNatsCurve encrypts req.Plaintext with the custodied NATS curve xkey
// named req.KeyID to req.RecipientPublicXKey.
func (n NatsClient) EncryptNatsCurve(ctx context.Context, req NatsCurveEncryptRequest) ([]byte, error) {
	ctx, cancel := n.c.withTimeout(ctx)
	defer cancel()
	resp, err := n.c.nats.EncryptNatsCurve(ctx, &pb.EncryptNatsCurveRequest{
		KeyId:               req.KeyID,
		RecipientPublicXkey: req.RecipientPublicXKey,
		Plaintext:           req.Plaintext,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetCiphertext(), nil
}

// DecryptNatsCurve decrypts req.Ciphertext with the custodied NATS curve xkey
// named req.KeyID, authenticating it against req.SenderPublicXKey.
func (c *Client) DecryptNatsCurve(ctx context.Context, req NatsCurveDecryptRequest) ([]byte, error) {
	return c.Nats().DecryptNatsCurve(ctx, req)
}

// DecryptNatsCurve decrypts req.Ciphertext with the custodied NATS curve xkey
// named req.KeyID, authenticating it against req.SenderPublicXKey.
func (n NatsClient) DecryptNatsCurve(ctx context.Context, req NatsCurveDecryptRequest) ([]byte, error) {
	ctx, cancel := n.c.withTimeout(ctx)
	defer cancel()
	resp, err := n.c.nats.DecryptNatsCurve(ctx, &pb.DecryptNatsCurveRequest{
		KeyId:            req.KeyID,
		SenderPublicXkey: req.SenderPublicXKey,
		Ciphertext:       req.Ciphertext,
	})
	if err != nil {
		return nil, statusError(err)
	}
	return resp.GetPlaintext(), nil
}

// SignNatsJwt validates and signs a caller-supplied NATS JWT claim document
// with the NATS signing key named req.KeyID.
func (c *Client) SignNatsJwt(ctx context.Context, req NatsJwtRequest) (*Credential, error) {
	return c.Nats().SignNatsJwt(ctx, req)
}

// SignNatsJwt validates and signs a caller-supplied NATS JWT claim document
// with the NATS signing key named req.KeyID.
func (n NatsClient) SignNatsJwt(ctx context.Context, req NatsJwtRequest) (*Credential, error) {
	claimsJSON, err := objectJSON(req.Claims, "nats jwt claims")
	if err != nil {
		return nil, err
	}
	return n.c.mint(ctx, func(ctx context.Context) (*pb.CredentialResponse, error) {
		return n.c.nats.SignNatsJwt(ctx, &pb.SignNatsJwtRequest{
			KeyId:        req.KeyID,
			ClaimsJson:   claimsJSON,
			ExpectedType: pb.NatsJwtType(req.ExpectedType),
			Ttl:          durationOrNil(req.TTL),
			ExpiresAt:    timestampOrNil(req.ExpiresAt),
			IssuedAt:     timestampOrNil(req.IssuedAt),
			JtiMode:      pb.NatsJtiMode(req.JtiMode),
		})
	})
}

// ValidateNatsJwt validates a presented NATS JWT against candidate catalog keys
// or public NKeys.
func (c *Client) ValidateNatsJwt(ctx context.Context, req ValidateNatsJwtRequest) (*NatsJwtValidation, error) {
	return c.Nats().ValidateNatsJwt(ctx, req)
}

// ValidateNatsJwt validates a presented NATS JWT against candidate catalog keys
// or public NKeys.
func (n NatsClient) ValidateNatsJwt(ctx context.Context, req ValidateNatsJwtRequest) (*NatsJwtValidation, error) {
	allowed := make([]*pb.AllowedNatsSigner, len(req.AllowedSigners))
	for i, signer := range req.AllowedSigners {
		protoSigner, err := signer.toProto()
		if err != nil {
			return nil, err
		}
		allowed[i] = protoSigner
	}
	ctx, cancel := n.c.withTimeout(ctx)
	defer cancel()
	resp, err := n.c.nats.ValidateNatsJwt(ctx, &pb.ValidateNatsJwtRequest{
		Jwt:            req.JWT,
		AllowedSigners: allowed,
		ExpectedType:   pb.NatsJwtType(req.ExpectedType),
	})
	if err != nil {
		return nil, statusError(err)
	}
	return natsJwtValidationFromProto(resp), nil
}

// IssueCertificate issues a DNS/IP-SAN X.509 leaf certificate from the backend
// PKI issue role named req.IssuerKeyID. The issuing CA key never leaves the
// backend; the freshly minted leaf private key is returned to the caller.
func (c *Client) IssueCertificate(ctx context.Context, req CertificateRequest) (*Certificate, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.minting.IssueCertificate(ctx, &pb.IssueCertificateRequest{
		IssuerKeyId: req.IssuerKeyID,
		CommonName:  req.CommonName,
		DnsSans:     req.DNSSANs,
		IpSans:      req.IPSANs,
		Ttl:         durationOrNil(req.TTL),
	})
	if err != nil {
		return nil, statusError(err)
	}
	return &Certificate{
		CertChainDER:  resp.GetCertChainDer(),
		PrivateKeyDER: resp.GetPrivateKeyDer(),
		CAChainDER:    resp.GetCaChainDer(),
	}, nil
}

// mint applies the default timeout, runs a credential-producing RPC, and maps
// the response and any error into the client's surface.
func (c *Client) mint(ctx context.Context, call func(context.Context) (*pb.CredentialResponse, error)) (*Credential, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := call(ctx)
	if err != nil {
		return nil, statusError(err)
	}
	return credentialFromProto(resp), nil
}

func credentialFromProto(r *pb.CredentialResponse) *Credential {
	out := &Credential{Token: r.GetToken()}
	if r.ExpiresAt != nil {
		out.ExpiresAt = r.GetExpiresAt().AsTime()
	}
	return out
}

func (s AllowedSigner) toProto() (*pb.AllowedNatsSigner, error) {
	if s.keyID != "" {
		return &pb.AllowedNatsSigner{
			Signer: &pb.AllowedNatsSigner_KeyId{KeyId: s.keyID},
		}, nil
	}
	if s.natsPublicKey == "" {
		return nil, fmt.Errorf("allowed signer must be constructed with AllowedSignerKeyID or AllowedSignerNatsPublicKey")
	}
	return &pb.AllowedNatsSigner{
		Signer: &pb.AllowedNatsSigner_NatsPublicKey{NatsPublicKey: s.natsPublicKey},
	}, nil
}

func natsJwtValidationFromProto(r *pb.ValidateNatsJwtResponse) *NatsJwtValidation {
	out := &NatsJwtValidation{
		Valid:              r.GetValid(),
		Reason:             NatsJwtValidationReason(r.GetReason()),
		Subject:            r.GetSubject(),
		Issuer:             r.GetIssuer(),
		MatchedSignerKeyID: r.GetMatchedSignerKeyId(),
		JWTType:            NatsJwtType(r.GetJwtType()),
	}
	if exp := r.GetExpiresAtUnix(); exp != 0 {
		out.ExpiresAt = time.Unix(int64(exp), 0).UTC()
	}
	if iat := r.GetIssuedAtUnix(); iat != 0 {
		out.IssuedAt = time.Unix(int64(iat), 0).UTC()
	}
	return out
}

// durationOrNil maps a non-positive duration to nil (omit = non-expiring /
// role default) and a positive one to a protobuf Duration.
func durationOrNil(d time.Duration) *durationpb.Duration {
	if d <= 0 {
		return nil
	}
	return durationpb.New(d)
}

// timestampOrNil maps the zero time to nil (omit) and any other to a protobuf
// Timestamp.
func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func optionalObjectJSON(value any, label string) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	return objectJSON(value, label)
}

func objectJSON(value any, label string) ([]byte, error) {
	if value == nil {
		return nil, fmt.Errorf("basil: invalid %s: missing JSON object", label)
	}
	var raw []byte
	switch v := value.(type) {
	case json.RawMessage:
		raw = v
	case []byte:
		raw = v
	case string:
		raw = []byte(v)
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("basil: invalid %s: %w", label, err)
		}
		raw = encoded
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("basil: invalid %s: missing JSON object", label)
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("basil: invalid %s: malformed JSON", label)
	}
	if raw[0] != '{' {
		return nil, fmt.Errorf("basil: invalid %s: expected JSON object", label)
	}
	return append([]byte(nil), raw...), nil
}
