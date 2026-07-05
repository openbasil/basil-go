// Package stream implements Basil's streaming, chunked authenticated encryption
// for large payloads and files, wire-identical to the Rust reference
// implementation (basil::stream) and the normative byte-level specification at
// docs/specs/streaming-encryption-format.md.
//
// The caller picks one suite ([SuiteAES256GCM], [SuiteChaCha20Poly1305], or one
// of the post-quantum ML-KEM suites [SuiteMLKEM512], [SuiteMLKEM768],
// [SuiteMLKEM1024]), and Basil owns the container format and every nonce. There
// is no caller-supplied nonce path.
//
// # Security properties
//
// Every chunk is sealed under a per-stream message key with a counter nonce, and
// its additional-authenticated-data binds the format version, suite, a random
// per-stream id, the chunk index, a final-chunk marker, the chunk length, and
// the declared chunk size. Records are therefore non-reorderable,
// non-truncatable (decryption fails closed if the stream ends before a
// final-marked chunk), non-replayable into another stream, and non-downgradable.
// All authentication failures collapse to [ErrAuthFailed].
//
// # Suites and the content-encryption key (CEK)
//
// The AEAD suites seal chunks directly under a 256-bit CEK established
// symmetrically: [GenerateCEK] mints a fresh random CEK per stream (secure
// default) and [EncryptAEAD] returns it; [ProvidedCEK] accepts a caller-held
// key. The ML-KEM suites generate a fresh CEK, wrap it once against the
// recipient's public encapsulation key, and write that envelope into the header;
// decryption recovers the CEK through a [CEKRecovery] seam.
//
// This package pulls in post-quantum crypto dependencies (circl) and lives in
// its own subpackage so the lean root basil package stays free of them.
package stream

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// CEKSource controls how the content-encryption key for an AEAD stream is
// established. Use [GenerateCEK] (secure default) or [ProvidedCEK].
type CEKSource struct {
	provided []byte // nil => generate a fresh random CEK
}

// GenerateCEK mints a fresh random 256-bit CEK per stream. [EncryptAEAD] returns
// the generated key so the caller can persist or transmit it.
func GenerateCEK() CEKSource { return CEKSource{} }

// ProvidedCEK uses a caller-supplied 32-byte content-encryption key.
func ProvidedCEK(key []byte) CEKSource { return CEKSource{provided: key} }

// chunkCrypto is the per-chunk crypto context shared by the encrypt and decrypt
// loops.
type chunkCrypto struct {
	suiteID    uint8
	chunkAEAD  chunkAEAD
	chunkSize  int
	streamID   *[StreamIDLen]byte
	messageKey []byte
}

// fillRandom fills buf with cryptographically secure random bytes.
func fillRandom(buf []byte) error {
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("basil/stream: rng failure: %w", err)
	}
	return nil
}

func validateChunkSize(chunkSize int) error {
	if chunkSize <= 0 || chunkSize > MaxChunkSize {
		return fmt.Errorf("%w: %d (must be 1..=%d)", ErrBadChunkSize, chunkSize, MaxChunkSize)
	}
	return nil
}

// EncryptAEAD encrypts src into dst under a symmetric AEAD suite
// ([SuiteAES256GCM] or [SuiteChaCha20Poly1305]). It returns the 32-byte
// content-encryption key that was used: freshly generated for [GenerateCEK], or
// a copy of the supplied key. That is what [DecryptAEAD] needs.
func EncryptAEAD(dst io.Writer, src io.Reader, suite Suite, cek CEKSource, chunkSize int) ([]byte, error) {
	if suite != SuiteAES256GCM && suite != SuiteChaCha20Poly1305 {
		return nil, fmt.Errorf("%w: %d is not an AEAD suite", ErrSuiteMismatch, suite)
	}
	if err := validateChunkSize(chunkSize); err != nil {
		return nil, err
	}
	alg, _ := chunkAEADForSuite(uint8(suite))

	key := make([]byte, CEKLen)
	if cek.provided == nil {
		if err := fillRandom(key); err != nil {
			return nil, err
		}
	} else {
		if len(cek.provided) != CEKLen {
			return nil, ErrBadCEKLength
		}
		copy(key, cek.provided)
	}

	var streamID [StreamIDLen]byte
	var streamSalt [StreamSaltLen]byte
	if err := fillRandom(streamID[:]); err != nil {
		return nil, err
	}
	if err := fillRandom(streamSalt[:]); err != nil {
		return nil, err
	}

	suiteID := uint8(suite)
	header := writeFixedHeader(make([]byte, 0, FixedHeaderLen), suiteID, uint32(chunkSize), &streamID, &streamSalt)

	messageKey, err := deriveMessageKey(&streamSalt, key, suiteID, &streamID)
	if err != nil {
		return nil, err
	}
	defer wipe(messageKey)

	c := &chunkCrypto{suiteID: suiteID, chunkAEAD: alg, chunkSize: chunkSize, streamID: &streamID, messageKey: messageKey}
	if err := writeChunks(dst, src, header, c); err != nil {
		return nil, err
	}
	return key, nil
}

// DecryptAEAD decrypts a symmetric-AEAD stream produced by [EncryptAEAD] into
// dst. cek is the 32-byte key returned by [EncryptAEAD]. It fails closed
// ([ErrSuiteMismatch], [ErrTruncated], [ErrAuthFailed], [ErrBadMagic],
// [ErrShortHeader]) on a malformed, truncated, reordered, or tampered stream.
func DecryptAEAD(dst io.Writer, src io.Reader, cek []byte) error {
	if len(cek) != CEKLen {
		return ErrBadCEKLength
	}
	header, err := readFixedHeader(src)
	if err != nil {
		return err
	}
	if Suite(header.suiteID) != SuiteAES256GCM && Suite(header.suiteID) != SuiteChaCha20Poly1305 {
		return fmt.Errorf("%w: container suite id %d is not valid for AEAD decryption", ErrSuiteMismatch, header.suiteID)
	}
	alg, _ := chunkAEADForSuite(header.suiteID)
	messageKey, err := deriveMessageKey(&header.streamSalt, cek, header.suiteID, &header.streamID)
	if err != nil {
		return err
	}
	defer wipe(messageKey)

	c := &chunkCrypto{suiteID: header.suiteID, chunkAEAD: alg, chunkSize: int(header.chunkSize), streamID: &header.streamID, messageKey: messageKey}
	return readChunks(dst, src, c)
}

// EncryptMLKEM encrypts src into dst under an ML-KEM suite ([SuiteMLKEM512],
// [SuiteMLKEM768], or [SuiteMLKEM1024]), wrapping a fresh CEK against publicKey
// (the recipient's FIPS-203 ML-KEM public encapsulation key). No broker is
// contacted. Chunks are sealed with AES-256-GCM.
func EncryptMLKEM(dst io.Writer, src io.Reader, suite Suite, publicKey []byte, chunkSize int) error {
	if _, ok := mlKemCiphertextLen(uint8(suite)); !ok {
		return fmt.Errorf("%w: %d is not an ML-KEM suite", ErrSuiteMismatch, suite)
	}
	if err := validateChunkSize(chunkSize); err != nil {
		return err
	}
	suiteID := uint8(suite)

	cek := make([]byte, CEKLen)
	if err := fillRandom(cek); err != nil {
		return err
	}
	defer wipe(cek)

	var streamID [StreamIDLen]byte
	var streamSalt [StreamSaltLen]byte
	if err := fillRandom(streamID[:]); err != nil {
		return err
	}
	if err := fillRandom(streamSalt[:]); err != nil {
		return err
	}

	cekwrapAAD := buildCEKWrapAAD(suiteID, &streamID)
	envelope, err := wrapCEK(publicKey, suiteID, cek, cekwrapAAD)
	if err != nil {
		return err
	}

	header := writeFixedHeader(make([]byte, 0, FixedHeaderLen), suiteID, uint32(chunkSize), &streamID, &streamSalt)
	header = append(header, serializeKEMHeader(envelope)...)

	messageKey, err := deriveMessageKey(&streamSalt, cek, suiteID, &streamID)
	if err != nil {
		return err
	}
	defer wipe(messageKey)

	c := &chunkCrypto{suiteID: suiteID, chunkAEAD: aeadAES256GCM, chunkSize: chunkSize, streamID: &streamID, messageKey: messageKey}
	return writeChunks(dst, src, header, c)
}

// DecryptMLKEM decrypts an ML-KEM stream produced by [EncryptMLKEM] into dst,
// recovering the CEK through recovery exactly once. It fails closed
// ([ErrSuiteMismatch], [ErrShortHeader], [ErrBadKEMCiphertext], a recovery
// error, [ErrTruncated], [ErrAuthFailed]) on any malformed or tampered input.
func DecryptMLKEM(ctx context.Context, dst io.Writer, src io.Reader, recovery CEKRecovery) error {
	header, err := readFixedHeader(src)
	if err != nil {
		return err
	}
	if _, ok := mlKemCiphertextLen(header.suiteID); !ok {
		return fmt.Errorf("%w: container suite id %d is not an ML-KEM stream", ErrSuiteMismatch, header.suiteID)
	}
	envelope, err := readKEMEnvelope(src, header.suiteID)
	if err != nil {
		return err
	}
	cekwrapAAD := buildCEKWrapAAD(header.suiteID, &header.streamID)
	cek, err := recovery.RecoverCEK(ctx, envelope, cekwrapAAD)
	if err != nil {
		return err
	}
	defer wipe(cek)
	if len(cek) != CEKLen {
		return ErrBadCEKLength
	}
	messageKey, err := deriveMessageKey(&header.streamSalt, cek, header.suiteID, &header.streamID)
	if err != nil {
		return err
	}
	defer wipe(messageKey)

	c := &chunkCrypto{suiteID: header.suiteID, chunkAEAD: aeadAES256GCM, chunkSize: int(header.chunkSize), streamID: &header.streamID, messageKey: messageKey}
	return readChunks(dst, src, c)
}

// writeChunks writes the header then the length-prefixed per-chunk AEAD records.
// It reads one chunk ahead so it can mark the last chunk final in its AAD.
func writeChunks(dst io.Writer, src io.Reader, header []byte, c *chunkCrypto) error {
	if _, err := dst.Write(header); err != nil {
		return err
	}
	chunkSizeU32 := uint32(c.chunkSize)

	current := make([]byte, c.chunkSize)
	have, err := readFull(src, current)
	if err != nil {
		return err
	}
	var index uint64
	for {
		next := make([]byte, c.chunkSize)
		nextHave, err := readFull(src, next)
		if err != nil {
			return err
		}
		isFinal := nextHave == 0

		aad := buildChunkAAD(c.suiteID, c.streamID, index, isFinal, uint32(have), chunkSizeU32)
		nonce := chunkNonce(index)
		record, err := aeadSeal(c.chunkAEAD, c.messageKey, &nonce, current[:have], aad)
		if err != nil {
			return err
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(record)))
		if _, err := dst.Write(lenBuf[:]); err != nil {
			return err
		}
		if _, err := dst.Write(record); err != nil {
			return err
		}

		index++
		if isFinal {
			break
		}
		current, have = next, nextHave
	}
	return nil
}

// readChunks reads and authenticates the length-prefixed per-chunk records into
// dst, failing closed on any tamper, reorder, or truncation.
func readChunks(dst io.Writer, src io.Reader, c *chunkCrypto) error {
	maxRecord := c.chunkSize + TagLen
	chunkSizeU32 := uint32(c.chunkSize)

	firstLen, present, err := readLenPrefix(src)
	if err != nil {
		return err
	}
	if !present {
		// An empty stream still carries one final-marked chunk; no records at all
		// means truncation.
		return ErrTruncated
	}
	current, err := readRecord(src, firstLen, maxRecord)
	if err != nil {
		return err
	}
	var index uint64
	for {
		nextLen, hasNext, err := readLenPrefix(src)
		if err != nil {
			return err
		}
		isFinal := !hasNext

		if len(current) < TagLen {
			return ErrAuthFailed
		}
		ptLen := len(current) - TagLen
		aad := buildChunkAAD(c.suiteID, c.streamID, index, isFinal, uint32(ptLen), chunkSizeU32)
		nonce := chunkNonce(index)
		plaintext, err := aeadOpen(c.chunkAEAD, c.messageKey, &nonce, current, aad)
		if err != nil {
			return err
		}
		// A non-final chunk must carry exactly chunk_size plaintext; this is also
		// bound in the AAD above, so a tampered framing already failed to open.
		if !isFinal && ptLen != c.chunkSize {
			return ErrAuthFailed
		}
		if _, err := dst.Write(plaintext); err != nil {
			return err
		}
		if isFinal {
			break
		}
		index++
		current, err = readRecord(src, nextLen, maxRecord)
		if err != nil {
			return err
		}
	}
	return nil
}

func readFixedHeader(src io.Reader) (streamHeader, error) {
	var buf [FixedHeaderLen]byte
	got, err := readFull(src, buf[:])
	if err != nil {
		return streamHeader{}, err
	}
	if got != FixedHeaderLen {
		return streamHeader{}, ErrShortHeader
	}
	return parseFixedHeader(buf[:])
}

func readKEMEnvelope(src io.Reader, suiteID uint8) (*KEMEnvelope, error) {
	expected, ok := mlKemCiphertextLen(suiteID)
	if !ok {
		return nil, ErrSuiteMismatch
	}
	kemCtLen, present, err := readLenPrefix(src)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, ErrShortHeader
	}
	if int(kemCtLen) != expected {
		return nil, ErrBadKEMCiphertext
	}
	encapsulatedKey, err := readRecordExact(src, expected)
	if err != nil {
		return nil, err
	}
	nonceBytes, err := readRecordExact(src, NonceLen)
	if err != nil {
		return nil, err
	}
	wrappedLen, present, err := readLenPrefix(src)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, ErrShortHeader
	}
	if int(wrappedLen) != CEKLen+TagLen {
		return nil, ErrBadKEMCiphertext
	}
	ciphertext, err := readRecordExact(src, CEKLen+TagLen)
	if err != nil {
		return nil, err
	}
	env := &KEMEnvelope{EncapsulatedKey: encapsulatedKey, Ciphertext: ciphertext}
	copy(env.Nonce[:], nonceBytes)
	return env, nil
}

// readRecord reads a length-prefixed record body, bounding its size against
// maxRecord.
func readRecord(src io.Reader, length uint32, maxRecord int) ([]byte, error) {
	if int(length) > maxRecord {
		return nil, ErrChunkTooLarge
	}
	return readRecordExact(src, int(length))
}

// readRecordExact reads exactly n bytes or fails closed with [ErrTruncated].
func readRecordExact(src io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	got, err := readFull(src, buf)
	if err != nil {
		return nil, err
	}
	if got != n {
		return nil, ErrTruncated
	}
	return buf, nil
}

// readLenPrefix reads a 4-byte big-endian length prefix. A clean end of stream
// at a record boundary returns (0, false, nil); a partial prefix is
// [ErrTruncated].
func readLenPrefix(src io.Reader) (uint32, bool, error) {
	var buf [4]byte
	got, err := readFull(src, buf[:])
	if err != nil {
		return 0, false, err
	}
	switch got {
	case 0:
		return 0, false, nil
	case 4:
		return binary.BigEndian.Uint32(buf[:]), true, nil
	default:
		return 0, false, ErrTruncated
	}
}

// readFull reads until buf is full or src reaches EOF, returning the bytes
// filled. A clean EOF (io.EOF) is not an error; it is signalled by a short
// count, mirroring the Rust reference's read_full.
func readFull(src io.Reader, buf []byte) (int, error) {
	filled := 0
	for filled < len(buf) {
		n, err := src.Read(buf[filled:])
		filled += n
		if err != nil {
			if err == io.EOF {
				return filled, nil
			}
			return filled, err
		}
		if n == 0 {
			return filled, nil
		}
	}
	return filled, nil
}
