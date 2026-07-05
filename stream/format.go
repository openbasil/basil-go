package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Container constants. These define the Basil streaming container format v1 and
// are byte-for-byte identical to the Rust reference implementation
// (basil::stream) and the normative spec at
// docs/specs/streaming-encryption-format.md. Every value here is load-bearing
// for cross-language interop.
const (
	// FormatVersion is the container format version byte.
	FormatVersion = 1
	// FixedHeaderLen is the length of the suite-independent header prefix.
	FixedHeaderLen = 61
	// TagLen is the AEAD authentication-tag length (AES-256-GCM and
	// ChaCha20-Poly1305 both use 16).
	TagLen = 16
	// NonceLen is the AEAD nonce length (both suites use a 96-bit nonce).
	NonceLen = 12
	// CEKLen is the content-encryption-key length (256-bit).
	CEKLen = 32
	// StreamIDLen is the per-stream random identifier length.
	StreamIDLen = 16
	// StreamSaltLen is the per-stream random HKDF salt length.
	StreamSaltLen = 32
	// DefaultChunkSize is the default plaintext chunk size: 64 KiB.
	DefaultChunkSize = 64 * 1024
	// MaxChunkSize is the maximum permitted plaintext chunk size: 1 MiB. It
	// bounds per-record buffering on decrypt so a malicious length prefix cannot
	// trigger unbounded allocation.
	MaxChunkSize = 1024 * 1024
)

// magic is the container magic: ASCII "BSLSTR" (Basil stream).
var magic = [6]byte{'B', 'S', 'L', 'S', 'T', 'R'}

// chunkAADMagic is the domain-separation tag prefixed to every per-chunk AAD.
var chunkAADMagic = [4]byte{'B', 'S', 'L', 'A'}

// cekWrapAADMagic is the domain-separation tag prefixed to the KEM-wrapped-CEK AAD.
var cekWrapAADMagic = [4]byte{'B', 'S', 'L', 'K'}

// streamCEKLabel is the HKDF info label binding the per-stream message key.
var streamCEKLabel = []byte("basil-stream-cek-v1")

// Suite identifies the algorithm suite of a stream. The 1-byte suite id in the
// header fully determines the chunk AEAD and whether a KEM header is present.
type Suite uint8

// Suite ids on the wire.
const (
	// SuiteAES256GCM seals chunks with AES-256-GCM; no KEM header.
	SuiteAES256GCM Suite = 1
	// SuiteChaCha20Poly1305 seals chunks with ChaCha20-Poly1305; no KEM header.
	SuiteChaCha20Poly1305 Suite = 2
	// SuiteMLKEM512 wraps the CEK with ML-KEM-512 + AES-256-GCM; chunks use AES-256-GCM.
	SuiteMLKEM512 Suite = 3
	// SuiteMLKEM768 wraps the CEK with ML-KEM-768 + AES-256-GCM; chunks use AES-256-GCM.
	SuiteMLKEM768 Suite = 4
	// SuiteMLKEM1024 wraps the CEK with ML-KEM-1024 + AES-256-GCM; chunks use AES-256-GCM.
	SuiteMLKEM1024 Suite = 5
)

// Sentinel errors. All authentication failures collapse to [ErrAuthFailed] so a
// caller learns nothing beyond "this stream did not verify". Errors that carry a
// value (suite id, chunk size) wrap the matching sentinel, so [errors.Is]
// matches and the value is visible in the message.
var (
	// ErrBadMagic is returned when the container magic bytes did not match.
	ErrBadMagic = errors.New("basil/stream: bad stream magic")
	// ErrUnsupportedVersion is returned for an unknown format version.
	ErrUnsupportedVersion = errors.New("basil/stream: unsupported stream format version")
	// ErrUnsupportedSuite is returned for an unknown algorithm suite id.
	ErrUnsupportedSuite = errors.New("basil/stream: unsupported stream suite id")
	// ErrReservedFlags is returned when the reserved header flags byte is non-zero.
	ErrReservedFlags = errors.New("basil/stream: reserved header flags must be zero")
	// ErrShortHeader is returned when the header is shorter than the format requires.
	ErrShortHeader = errors.New("basil/stream: truncated or malformed stream header")
	// ErrBadChunkSize is returned for a chunk size of 0 or above MaxChunkSize.
	ErrBadChunkSize = errors.New("basil/stream: invalid chunk size")
	// ErrChunkTooLarge is returned when a record length prefix implies a
	// plaintext chunk above the limit.
	ErrChunkTooLarge = errors.New("basil/stream: chunk record too large")
	// ErrSuiteMismatch is returned when a decrypt entry point is called for a
	// different suite family than the container actually uses.
	ErrSuiteMismatch = errors.New("basil/stream: stream suite mismatch")
	// ErrBadPublicKey is returned for a malformed ML-KEM public encapsulation key.
	ErrBadPublicKey = errors.New("basil/stream: invalid ML-KEM public key")
	// ErrBadCEKLength is returned when a recovered or supplied CEK is not CEKLen bytes.
	ErrBadCEKLength = errors.New("basil/stream: invalid content-encryption key length")
	// ErrBadKEMCiphertext is returned for a malformed ML-KEM ciphertext or KEM header.
	ErrBadKEMCiphertext = errors.New("basil/stream: invalid ML-KEM ciphertext")
	// ErrTruncated is returned when the stream ended before a final-marked chunk
	// was authenticated.
	ErrTruncated = errors.New("basil/stream: stream truncated: missing final chunk")
	// ErrAuthFailed is returned for any AEAD authentication failure: wrong key,
	// tampered data/AAD, reordered or truncated chunk, or a downgraded header.
	ErrAuthFailed = errors.New("basil/stream: stream authentication failed")
	// ErrKDFFailed is returned when HKDF key derivation fails.
	ErrKDFFailed = errors.New("basil/stream: key derivation failed")
	// ErrSealFailed is returned when AEAD sealing fails.
	ErrSealFailed = errors.New("basil/stream: seal failed")
)

// chunkAEAD is the AEAD used to seal individual chunks.
type chunkAEAD uint8

const (
	aeadAES256GCM chunkAEAD = iota
	aeadChaCha20Poly1305
)

// streamHeader holds the parsed fixed-header fields shared by every suite.
type streamHeader struct {
	suiteID    uint8
	chunkSize  uint32
	streamID   [StreamIDLen]byte
	streamSalt [StreamSaltLen]byte
}

// chunkAEADForSuite resolves the chunk AEAD used by a suite id. The boolean is
// false for an unknown suite.
func chunkAEADForSuite(suiteID uint8) (chunkAEAD, bool) {
	switch Suite(suiteID) {
	case SuiteAES256GCM, SuiteMLKEM512, SuiteMLKEM768, SuiteMLKEM1024:
		return aeadAES256GCM, true
	case SuiteChaCha20Poly1305:
		return aeadChaCha20Poly1305, true
	default:
		return 0, false
	}
}

// mlKemCiphertextLen returns the FIPS-203 ML-KEM ciphertext length for an ML-KEM
// suite. The boolean is false for a non-ML-KEM suite.
func mlKemCiphertextLen(suiteID uint8) (int, bool) {
	switch Suite(suiteID) {
	case SuiteMLKEM512:
		return 768, true
	case SuiteMLKEM768:
		return 1088, true
	case SuiteMLKEM1024:
		return 1568, true
	default:
		return 0, false
	}
}

// kemToken returns the ASCII suite token bound into the CEK-wrap HKDF info.
func kemToken(suiteID uint8) (string, bool) {
	switch Suite(suiteID) {
	case SuiteMLKEM512:
		return "ml-kem-512", true
	case SuiteMLKEM768:
		return "ml-kem-768", true
	case SuiteMLKEM1024:
		return "ml-kem-1024", true
	default:
		return "", false
	}
}

// writeFixedHeader serializes the fixed header prefix, appending it to out.
func writeFixedHeader(out []byte, suiteID uint8, chunkSize uint32, streamID *[StreamIDLen]byte, streamSalt *[StreamSaltLen]byte) []byte {
	out = append(out, magic[:]...)
	out = append(out, FormatVersion)
	out = append(out, suiteID)
	out = append(out, 0) // reserved flags
	var sz [4]byte
	binary.BigEndian.PutUint32(sz[:], chunkSize)
	out = append(out, sz[:]...)
	out = append(out, streamID[:]...)
	out = append(out, streamSalt[:]...)
	return out
}

// parseFixedHeader parses and validates the FixedHeaderLen header prefix.
func parseFixedHeader(buf []byte) (streamHeader, error) {
	var h streamHeader
	if len(buf) < FixedHeaderLen {
		return h, ErrShortHeader
	}
	if [6]byte(buf[0:6]) != magic {
		return h, ErrBadMagic
	}
	if buf[6] != FormatVersion {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedVersion, buf[6])
	}
	suiteID := buf[7]
	if buf[8] != 0 {
		return h, ErrReservedFlags
	}
	if _, ok := chunkAEADForSuite(suiteID); !ok {
		return h, fmt.Errorf("%w: %d", ErrUnsupportedSuite, suiteID)
	}
	chunkSize := binary.BigEndian.Uint32(buf[9:13])
	if chunkSize < 1 || chunkSize > MaxChunkSize {
		return h, fmt.Errorf("%w: %d (must be 1..=%d)", ErrBadChunkSize, chunkSize, MaxChunkSize)
	}
	h.suiteID = suiteID
	h.chunkSize = chunkSize
	copy(h.streamID[:], buf[13:29])
	copy(h.streamSalt[:], buf[29:61])
	return h, nil
}

// buildChunkAAD builds the 39-byte per-chunk AEAD additional-authenticated-data:
// "BSLA" | version | suite_id | stream_id[16] | chunk_index[8] | final_flag |
// chunk_plaintext_len[4] | chunk_size[4]  (big-endian integers).
func buildChunkAAD(suiteID uint8, streamID *[StreamIDLen]byte, chunkIndex uint64, isFinal bool, chunkPlaintextLen, chunkSize uint32) []byte {
	aad := make([]byte, 0, 39)
	aad = append(aad, chunkAADMagic[:]...)
	aad = append(aad, FormatVersion)
	aad = append(aad, suiteID)
	aad = append(aad, streamID[:]...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], chunkIndex)
	aad = append(aad, u8[:]...)
	if isFinal {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], chunkPlaintextLen)
	aad = append(aad, u4[:]...)
	binary.BigEndian.PutUint32(u4[:], chunkSize)
	aad = append(aad, u4[:]...)
	return aad
}

// buildCEKWrapAAD builds the 22-byte AAD that binds a KEM-wrapped CEK to its
// stream: "BSLK" | version | suite_id | stream_id[16].
func buildCEKWrapAAD(suiteID uint8, streamID *[StreamIDLen]byte) []byte {
	aad := make([]byte, 0, 22)
	aad = append(aad, cekWrapAADMagic[:]...)
	aad = append(aad, FormatVersion)
	aad = append(aad, suiteID)
	aad = append(aad, streamID[:]...)
	return aad
}

// chunkNonce derives the per-chunk nonce: 4 zero bytes followed by the 64-bit
// big-endian chunk index. The per-stream message key is unique per stream, so a
// counter nonce guarantees (key, nonce) uniqueness.
func chunkNonce(chunkIndex uint64) [NonceLen]byte {
	var nonce [NonceLen]byte
	binary.BigEndian.PutUint64(nonce[4:], chunkIndex)
	return nonce
}

// deriveMessageKey derives the per-stream message key
// K_msg = HKDF-SHA256(salt=streamSalt, ikm=cek,
//
//	info="basil-stream-cek-v1" | suite_id | stream_id) first 32 bytes.
//
// The returned slice is owned by the caller, which should wipe it after use.
func deriveMessageKey(streamSalt *[StreamSaltLen]byte, cek []byte, suiteID uint8, streamID *[StreamIDLen]byte) ([]byte, error) {
	info := make([]byte, 0, len(streamCEKLabel)+1+StreamIDLen)
	info = append(info, streamCEKLabel...)
	info = append(info, suiteID)
	info = append(info, streamID[:]...)
	okm, err := hkdf.Key(sha256.New, cek, streamSalt[:], string(info), CEKLen)
	if err != nil {
		return nil, ErrKDFFailed
	}
	return okm, nil
}

// newAEAD constructs the chunk AEAD cipher for a 32-byte key.
func newAEAD(alg chunkAEAD, key []byte) (cipher.AEAD, error) {
	switch alg {
	case aeadAES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrSealFailed
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrSealFailed
		}
		return gcm, nil
	case aeadChaCha20Poly1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, ErrSealFailed
		}
		return aead, nil
	default:
		return nil, ErrSealFailed
	}
}

// aeadSeal seals one chunk under the per-stream message key.
func aeadSeal(alg chunkAEAD, key []byte, nonce *[NonceLen]byte, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(alg, key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce[:], plaintext, aad), nil
}

// aeadOpen opens one chunk under the per-stream message key. Any authentication
// failure collapses to ErrAuthFailed.
func aeadOpen(alg chunkAEAD, key []byte, nonce *[NonceLen]byte, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(alg, key)
	if err != nil {
		return nil, ErrAuthFailed
	}
	pt, err := aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	return pt, nil
}

// wipe zeroes a byte slice in place. It is best-effort: Go may keep copies the
// runtime made, but it bounds the lifetime of key material the caller holds.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
