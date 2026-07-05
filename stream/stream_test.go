package stream

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// seed is a deterministic 64-byte ML-KEM seed (FIPS-203 d||z) for tests.
func seed() []byte { return bytes.Repeat([]byte{0x42}, 64) }

// payload builds a deterministic multi-chunk payload of len bytes.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func encryptAEADBytes(t *testing.T, suite Suite, data []byte, chunkSize int) (ct, cek []byte) {
	t.Helper()
	var buf bytes.Buffer
	key, err := EncryptAEAD(&buf, bytes.NewReader(data), suite, GenerateCEK(), chunkSize)
	if err != nil {
		t.Fatalf("EncryptAEAD: %v", err)
	}
	return buf.Bytes(), key
}

func decryptAEADBytes(ct, cek []byte) ([]byte, error) {
	var out bytes.Buffer
	err := DecryptAEAD(&out, bytes.NewReader(ct), cek)
	return out.Bytes(), err
}

func encryptMLKEMBytes(t *testing.T, suite Suite, data []byte, chunkSize int) []byte {
	t.Helper()
	pub, err := PublicKeyFromSeed(seed(), suite)
	if err != nil {
		t.Fatalf("PublicKeyFromSeed: %v", err)
	}
	var buf bytes.Buffer
	if err := EncryptMLKEM(&buf, bytes.NewReader(data), suite, pub, chunkSize); err != nil {
		t.Fatalf("EncryptMLKEM: %v", err)
	}
	return buf.Bytes()
}

func decryptMLKEMBytes(suite Suite, ct []byte) ([]byte, error) {
	var out bytes.Buffer
	rec := NewLocalSeedCEKRecovery(seed(), suite)
	err := DecryptMLKEM(context.Background(), &out, bytes.NewReader(ct), rec)
	return out.Bytes(), err
}

func TestAEADRoundTripMultiChunk(t *testing.T) {
	data := payload(200)
	for _, suite := range []Suite{SuiteAES256GCM, SuiteChaCha20Poly1305} {
		ct, cek := encryptAEADBytes(t, suite, data, 64)
		got, err := decryptAEADBytes(ct, cek)
		if err != nil {
			t.Fatalf("suite %d decrypt: %v", suite, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("suite %d round-trip mismatch", suite)
		}
	}
}

func TestMLKEMRoundTripMultiChunk(t *testing.T) {
	data := payload(500)
	for _, suite := range []Suite{SuiteMLKEM512, SuiteMLKEM768, SuiteMLKEM1024} {
		ct := encryptMLKEMBytes(t, suite, data, 128)
		got, err := decryptMLKEMBytes(suite, ct)
		if err != nil {
			t.Fatalf("suite %d decrypt: %v", suite, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("suite %d round-trip mismatch", suite)
		}
	}
}

func TestEmptyPayloadRoundTrips(t *testing.T) {
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, nil, 64)
	got, err := decryptAEADBytes(ct, cek)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
	// Empty payload => single final 16-byte tag-only record: header + 4-byte len + 16.
	if len(ct) != FixedHeaderLen+4+TagLen {
		t.Fatalf("empty container length: got %d want %d", len(ct), FixedHeaderLen+4+TagLen)
	}
}

func TestExactMultipleOfChunkSize(t *testing.T) {
	const chunk = 32
	// Two full chunks exactly => third (empty) chunk is the final marker.
	data := payload(chunk * 2)
	for _, suite := range []Suite{SuiteAES256GCM, SuiteChaCha20Poly1305, SuiteMLKEM768} {
		var ct []byte
		var cek []byte
		if suite == SuiteMLKEM768 {
			ct = encryptMLKEMBytes(t, suite, data, chunk)
		} else {
			ct, cek = encryptAEADBytes(t, suite, data, chunk)
		}
		var got []byte
		var err error
		if suite == SuiteMLKEM768 {
			got, err = decryptMLKEMBytes(suite, ct)
		} else {
			got, err = decryptAEADBytes(ct, cek)
		}
		if err != nil {
			t.Fatalf("suite %d decrypt: %v", suite, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("suite %d exact-multiple mismatch", suite)
		}
	}
}

func TestCallerProvidedCEK(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, CEKLen)
	data := payload(150)
	var buf bytes.Buffer
	returned, err := EncryptAEAD(&buf, bytes.NewReader(data), SuiteAES256GCM, ProvidedCEK(key), 64)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !bytes.Equal(returned, key) {
		t.Fatalf("returned CEK should equal supplied key")
	}
	got, err := decryptAEADBytes(buf.Bytes(), key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("provided-CEK round-trip mismatch")
	}
}

func TestProvidedCEKBadLength(t *testing.T) {
	var buf bytes.Buffer
	_, err := EncryptAEAD(&buf, bytes.NewReader(payload(10)), SuiteAES256GCM, ProvidedCEK([]byte{1, 2, 3}), 64)
	if !errors.Is(err, ErrBadCEKLength) {
		t.Fatalf("want ErrBadCEKLength, got %v", err)
	}
}

func TestShortAndMalformedHeaders(t *testing.T) {
	key := make([]byte, CEKLen)
	if _, err := decryptAEADBytes(nil, key); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("empty input: want ErrShortHeader, got %v", err)
	}
	if _, err := decryptAEADBytes(make([]byte, 10), key); !errors.Is(err, ErrShortHeader) {
		t.Fatalf("short header: want ErrShortHeader, got %v", err)
	}
	bad := bytes.Repeat([]byte{0xFF}, FixedHeaderLen)
	if _, err := decryptAEADBytes(bad, key); !errors.Is(err, ErrBadMagic) {
		t.Fatalf("bad magic: want ErrBadMagic, got %v", err)
	}
}

func TestTamperedCiphertextFailsClosed(t *testing.T) {
	data := payload(96)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	ct[FixedHeaderLen+4] ^= 0xFF // first record body byte
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestReorderedChunksFailClosed(t *testing.T) {
	data := payload(96) // three full 32-byte chunks
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	recordBody := 32 + TagLen
	r0 := FixedHeaderLen + 4
	r1 := r0 + recordBody + 4
	for off := 0; off < recordBody; off++ {
		ct[r0+off], ct[r1+off] = ct[r1+off], ct[r0+off]
	}
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestDroppedFinalChunkDetected(t *testing.T) {
	data := payload(96)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	recordBody := 32 + TagLen
	truncated := ct[:FixedHeaderLen+2*(4+recordBody)]
	if _, err := decryptAEADBytes(truncated, cek); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestMidRecordTruncationDetected(t *testing.T) {
	data := payload(96)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	truncated := ct[:len(ct)-8]
	if _, err := decryptAEADBytes(truncated, cek); !(errors.Is(err, ErrTruncated) || errors.Is(err, ErrAuthFailed)) {
		t.Fatalf("want ErrTruncated or ErrAuthFailed, got %v", err)
	}
}

func TestDowngradedSuiteFailsClosed(t *testing.T) {
	data := payload(96)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	if ct[7] != 1 {
		t.Fatalf("expected suite id 1 at offset 7, got %d", ct[7])
	}
	ct[7] = 2 // downgrade to ChaCha20
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestUnknownSuiteRejected(t *testing.T) {
	data := payload(64)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	ct[7] = 99
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrUnsupportedSuite) {
		t.Fatalf("want ErrUnsupportedSuite, got %v", err)
	}
}

func TestNonzeroReservedFlagsRejected(t *testing.T) {
	data := payload(64)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	ct[8] = 1
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrReservedFlags) {
		t.Fatalf("want ErrReservedFlags, got %v", err)
	}
}

func TestBadChunkSizeInHeaderRejected(t *testing.T) {
	data := payload(64)
	ct, cek := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	binary.BigEndian.PutUint32(ct[9:13], 0) // chunk_size = 0
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrBadChunkSize) {
		t.Fatalf("want ErrBadChunkSize, got %v", err)
	}
	binary.BigEndian.PutUint32(ct[9:13], MaxChunkSize+1)
	if _, err := decryptAEADBytes(ct, cek); !errors.Is(err, ErrBadChunkSize) {
		t.Fatalf("want ErrBadChunkSize (over max), got %v", err)
	}
}

func TestEncryptBadChunkSizeRejected(t *testing.T) {
	var buf bytes.Buffer
	for _, sz := range []int{0, MaxChunkSize + 1} {
		if _, err := EncryptAEAD(&buf, bytes.NewReader(nil), SuiteAES256GCM, GenerateCEK(), sz); !errors.Is(err, ErrBadChunkSize) {
			t.Fatalf("chunk size %d: want ErrBadChunkSize, got %v", sz, err)
		}
	}
}

func TestAEADDecryptOnMLKEMStreamIsSuiteMismatch(t *testing.T) {
	ct := encryptMLKEMBytes(t, SuiteMLKEM768, payload(128), 64)
	if _, err := decryptAEADBytes(ct, make([]byte, CEKLen)); !errors.Is(err, ErrSuiteMismatch) {
		t.Fatalf("want ErrSuiteMismatch, got %v", err)
	}
}

func TestMLKEMDecryptOnAEADStreamIsSuiteMismatch(t *testing.T) {
	ct, _ := encryptAEADBytes(t, SuiteAES256GCM, payload(128), 64)
	if _, err := decryptMLKEMBytes(SuiteMLKEM768, ct); !errors.Is(err, ErrSuiteMismatch) {
		t.Fatalf("want ErrSuiteMismatch, got %v", err)
	}
}

func TestMLKEMTamperedCiphertextFailsClosed(t *testing.T) {
	suite := SuiteMLKEM768
	ct := encryptMLKEMBytes(t, suite, payload(300), 128)
	ctLen, _ := mlKemCiphertextLen(uint8(suite))
	kemHeader := 4 + ctLen + NonceLen + 4 + (CEKLen + TagLen)
	firstRecordBody := FixedHeaderLen + kemHeader + 4
	ct[firstRecordBody] ^= 0xFF
	if _, err := decryptMLKEMBytes(suite, ct); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestMLKEMEnvelopeAppearsExactlyOnce(t *testing.T) {
	suite := SuiteMLKEM768
	ct := encryptMLKEMBytes(t, suite, payload(700), 128)
	kemCtLen := int(binary.BigEndian.Uint32(ct[FixedHeaderLen : FixedHeaderLen+4]))
	wantLen, _ := mlKemCiphertextLen(uint8(suite))
	if kemCtLen != wantLen {
		t.Fatalf("kem_ct_len: got %d want %d", kemCtLen, wantLen)
	}
	encKey := ct[FixedHeaderLen+4 : FixedHeaderLen+4+kemCtLen]
	if n := bytes.Count(ct, encKey); n != 1 {
		t.Fatalf("KEM envelope must appear exactly once, found %d", n)
	}
}

func TestMLKEMWrongSeedFailsClosed(t *testing.T) {
	suite := SuiteMLKEM768
	ct := encryptMLKEMBytes(t, suite, payload(128), 64)
	var out bytes.Buffer
	wrong := NewLocalSeedCEKRecovery(bytes.Repeat([]byte{0x07}, 64), suite)
	if err := DecryptMLKEM(context.Background(), &out, bytes.NewReader(ct), wrong); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestMLKEMKEMHeaderLengthMismatch(t *testing.T) {
	suite := SuiteMLKEM768
	ct := encryptMLKEMBytes(t, suite, payload(64), 64)
	// Corrupt kem_ct_len so it no longer matches the suite's ciphertext length.
	bad := append([]byte(nil), ct...)
	binary.BigEndian.PutUint32(bad[FixedHeaderLen:FixedHeaderLen+4], 1234)
	if _, err := decryptMLKEMBytes(suite, bad); !errors.Is(err, ErrBadKEMCiphertext) {
		t.Fatalf("want ErrBadKEMCiphertext (kem_ct_len), got %v", err)
	}
	// Corrupt wrapped_cek_len so it no longer equals 48.
	ctLen, _ := mlKemCiphertextLen(uint8(suite))
	wrappedLenOff := FixedHeaderLen + 4 + ctLen + NonceLen
	bad2 := append([]byte(nil), ct...)
	binary.BigEndian.PutUint32(bad2[wrappedLenOff:wrappedLenOff+4], 99)
	if _, err := decryptMLKEMBytes(suite, bad2); !errors.Is(err, ErrBadKEMCiphertext) {
		t.Fatalf("want ErrBadKEMCiphertext (wrapped_cek_len), got %v", err)
	}
}

func TestWrongCEKFailsClosed(t *testing.T) {
	data := payload(96)
	ct, _ := encryptAEADBytes(t, SuiteAES256GCM, data, 32)
	if _, err := decryptAEADBytes(ct, make([]byte, CEKLen)); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("want ErrAuthFailed, got %v", err)
	}
}

func TestMLKEMInternalRoundTripAllLevels(t *testing.T) {
	// Self-contained ML-KEM encap (PublicKeyFromSeed) + decap (LocalSeedCEKRecovery)
	// proof for every parameter set over a multi-chunk payload.
	data := payload(1000)
	for _, suite := range []Suite{SuiteMLKEM512, SuiteMLKEM768, SuiteMLKEM1024} {
		ct := encryptMLKEMBytes(t, suite, data, 256)
		got, err := decryptMLKEMBytes(suite, ct)
		if err != nil {
			t.Fatalf("suite %d: %v", suite, err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("suite %d internal round-trip mismatch", suite)
		}
	}
}
