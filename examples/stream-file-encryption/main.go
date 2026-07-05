// Command stream-file-encryption encrypts a multi-mebibyte file with Basil's
// streaming, chunked AEAD (basil/stream) and proves it round-trips byte-for-byte
// in two modes: symmetric AES-256-GCM with a locally generated content-
// encryption key, and post-quantum ML-KEM-768 whose CEK is recovered through
// the broker (the decapsulation key stays custodied in the vault). A final
// tamper case flips one ciphertext byte and asserts decryption fails closed.
//
// The container is wire-identical to the Rust reference basil::stream and the
// normative spec at docs/specs/streaming-encryption-format.md; a file written
// here decrypts unchanged on the Rust side and vice versa.
//
// Basil owns the container format and every nonce (there is no caller-supplied
// nonce path), and prints one machine-checkable `PASS ...` line per proven
// property, exiting non-zero on the first failure.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openbasil/basil-go/basil"
	"github.com/openbasil/basil-go/stream"
)

const (
	// fileSize is a few MiB so the stream spans many chunks.
	fileSize = 4 * 1024 * 1024
	// chunkSize splits the payload into ~64 sealed records.
	chunkSize = 64 * 1024
)

type config struct {
	socket   string
	kemKeyID string
	workDir  string
}

func loadConfig() config {
	return config{
		socket:   envOr("BASIL_SOCKET", "/tmp/basil-stream-file/agent.sock"),
		kemKeyID: envOr("BASIL_KEM_KEY_ID", "app.stream_seal"),
		workDir:  envOr("STREAM_FILE_DIR", os.TempDir()),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(loadConfig()); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL:", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	client, err := basil.Dial(cfg.socket)
	if err != nil {
		return fmt.Errorf("dial broker at %s: %w", cfg.socket, err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	plainPath := filepath.Join(cfg.workDir, "plain.bin")
	if err := generateFile(plainPath, fileSize); err != nil {
		return err
	}
	plainDigest, err := digest(plainPath)
	if err != nil {
		return err
	}
	fmt.Printf("PASS input file bytes=%d chunk_size=%d\n", fileSize, chunkSize)

	if err := aesRoundTrip(cfg.workDir, plainPath, plainDigest); err != nil {
		return err
	}
	if err := mlkemRoundTrip(ctx, client, cfg, plainPath, plainDigest); err != nil {
		return err
	}
	return tamperFailsClosed(cfg.workDir, plainPath)
}

// aesRoundTrip encrypts the file under AES-256-GCM with a freshly generated CEK,
// decrypts it back, and asserts the plaintext is byte-identical.
func aesRoundTrip(workDir, plainPath string, plainDigest [32]byte) error {
	ctPath := filepath.Join(workDir, "aes.ct")
	outPath := filepath.Join(workDir, "aes.out")

	in, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer in.Close()
	ctOut, err := os.Create(ctPath)
	if err != nil {
		return err
	}
	cek, err := stream.EncryptAEAD(ctOut, in, stream.SuiteAES256GCM, stream.GenerateCEK(), chunkSize)
	if err != nil {
		ctOut.Close()
		return fmt.Errorf("AES encrypt: %w", err)
	}
	if err := ctOut.Close(); err != nil {
		return err
	}
	fmt.Println("PASS aes-256-gcm encrypt multi-chunk")

	ctIn, err := os.Open(ctPath)
	if err != nil {
		return err
	}
	defer ctIn.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	if err := stream.DecryptAEAD(out, ctIn, cek); err != nil {
		out.Close()
		return fmt.Errorf("AES decrypt: %w", err)
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := assertSameDigest(outPath, plainDigest); err != nil {
		return fmt.Errorf("AES round-trip: %w", err)
	}
	fmt.Println("PASS aes-256-gcm roundtrip byte-identical")
	return nil
}

// mlkemRoundTrip provisions a custodied ML-KEM-768 sealing key, fetches its
// public encapsulation key, encrypts the file against it locally, then decrypts
// by recovering the CEK through the broker: the decapsulation key never leaves
// the vault.
func mlkemRoundTrip(ctx context.Context, client *basil.Client, cfg config, plainPath string, plainDigest [32]byte) error {
	if _, err := client.NewKey(ctx, cfg.kemKeyID, basil.KeyTypeMLKEM768); err != nil {
		return fmt.Errorf("provision custodied ML-KEM-768 key %s: %w", cfg.kemKeyID, err)
	}
	pub, err := client.GetPublicKey(ctx, cfg.kemKeyID, nil)
	if err != nil {
		return fmt.Errorf("fetch ML-KEM public key: %w", err)
	}
	fmt.Printf("PASS ml-kem-768 provisioned key=%s public_len=%d\n", cfg.kemKeyID, len(pub.Bytes))

	ctPath := filepath.Join(cfg.workDir, "mlkem.ct")
	outPath := filepath.Join(cfg.workDir, "mlkem.out")

	in, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer in.Close()
	ctOut, err := os.Create(ctPath)
	if err != nil {
		return err
	}
	if err := stream.EncryptMLKEM(ctOut, in, stream.SuiteMLKEM768, pub.Bytes, chunkSize); err != nil {
		ctOut.Close()
		return fmt.Errorf("ML-KEM encrypt: %w", err)
	}
	if err := ctOut.Close(); err != nil {
		return err
	}
	fmt.Println("PASS ml-kem-768 encrypt multi-chunk")

	ctIn, err := os.Open(ctPath)
	if err != nil {
		return err
	}
	defer ctIn.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	recovery := stream.NewBrokerCEKRecovery(client, cfg.kemKeyID, stream.SuiteMLKEM768)
	if err := stream.DecryptMLKEM(ctx, out, ctIn, recovery); err != nil {
		out.Close()
		return fmt.Errorf("ML-KEM decrypt (broker CEK recovery): %w", err)
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := assertSameDigest(outPath, plainDigest); err != nil {
		return fmt.Errorf("ML-KEM round-trip: %w", err)
	}
	fmt.Println("PASS ml-kem-768 roundtrip byte-identical broker-recovered-cek")
	return nil
}

// tamperFailsClosed AES-encrypts the file to a buffer, flips one ciphertext
// byte, and asserts decryption returns the authentication-failure error.
func tamperFailsClosed(workDir, plainPath string) error {
	in, err := os.Open(plainPath)
	if err != nil {
		return err
	}
	defer in.Close()

	var buf bytes.Buffer
	cek, err := stream.EncryptAEAD(&buf, in, stream.SuiteAES256GCM, stream.GenerateCEK(), chunkSize)
	if err != nil {
		return fmt.Errorf("tamper setup encrypt: %w", err)
	}
	ct := buf.Bytes()

	// Flip the first byte of the first record body (just past the fixed header
	// and its 4-byte length prefix).
	flip := stream.FixedHeaderLen + 4
	if flip >= len(ct) {
		return errors.New("tamper: ciphertext shorter than a single record")
	}
	ct[flip] ^= 0xFF

	if err := stream.DecryptAEAD(io.Discard, bytes.NewReader(ct), cek); !errors.Is(err, stream.ErrAuthFailed) {
		return fmt.Errorf("tamper: want ErrAuthFailed, got %v", err)
	}
	fmt.Println("PASS tamper fails-closed ErrAuthFailed")
	return nil
}

// --- small file / crypto helpers -------------------------------------------

func generateFile(path string, size int) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.CopyN(f, rand.Reader, int64(size)); err != nil {
		return fmt.Errorf("generate %s: %w", path, err)
	}
	return f.Close()
}

func digest(path string) ([32]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

func assertSameDigest(path string, want [32]byte) error {
	got, err := digest(path)
	if err != nil {
		return err
	}
	if got != want {
		return errors.New("decrypted output differs from the plaintext")
	}
	return nil
}
