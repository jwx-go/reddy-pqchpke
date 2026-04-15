package pqchpke_test

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"

	pqchpke "github.com/jwx-go/reddy-pqchpke/v4"
)

const samplePlaintext = "draft-reddy hybrid HPKE plaintext"

// sampleSeed is a fixed 32-byte X-Wing seed used across deterministic
// tests. Not cryptographically random — test use only.
var sampleSeed = [pqchpke.PrivateKeySize]byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

func TestGenerateKey(t *testing.T) {
	sk, err := pqchpke.GenerateKey()
	require.NoError(t, err, "GenerateKey should succeed")
	require.NotNil(t, sk)

	seed := sk.Seed()
	require.Len(t, seed, pqchpke.PrivateKeySize, "seed should be 32 bytes")

	pk := sk.Public()
	require.NotNil(t, pk)
	require.Len(t, pk.Bytes(), pqchpke.PublicKeySize, "public key should be 1216 bytes")
}

func TestPrivateKeyFromSeedRoundTrip(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)
	require.NotNil(t, sk)

	got := sk.Seed()
	require.Equal(t, sampleSeed[:], got, "seed should round-trip")
}

func TestPrivateKeyFromSeed_WrongSize(t *testing.T) {
	_, err := pqchpke.PrivateKeyFromSeed(make([]byte, 31))
	require.Error(t, err, "31-byte seed should be rejected")

	_, err = pqchpke.PrivateKeyFromSeed(make([]byte, 33))
	require.Error(t, err, "33-byte seed should be rejected")

	_, err = pqchpke.PrivateKeyFromSeed(nil)
	require.Error(t, err, "nil seed should be rejected")
}

func TestPublicKeyFromBytes_WrongSize(t *testing.T) {
	_, err := pqchpke.PublicKeyFromBytes(make([]byte, 1215))
	require.Error(t, err, "1215-byte pub should be rejected")

	_, err = pqchpke.PublicKeyFromBytes(make([]byte, 1217))
	require.Error(t, err, "1217-byte pub should be rejected")

	_, err = pqchpke.PublicKeyFromBytes(nil)
	require.Error(t, err, "nil pub should be rejected")
}

func TestJWERoundTrip_HPKE10KE(t *testing.T) {
	// HPKE-10-KE uses AES-256-GCM *inside* HPKE to seal the CEK. The
	// JWE content encryption (the `enc` header) is independent; we use
	// A256GCM here but it's bound into the HPKE info, not the HPKE AEAD.
	testJWERoundTrip(t, pqchpke.HPKE10(), jwa.A256GCM())
}

func TestJWERoundTrip_HPKE11KE(t *testing.T) {
	// HPKE-11-KE uses ChaCha20-Poly1305 inside HPKE. Varying the JWE
	// content encryption (A128GCM here) verifies that calg flows
	// through HybridPublicKey.EncryptHPKE into the HPKE info bytes.
	testJWERoundTrip(t, pqchpke.HPKE11(), jwa.A128GCM())
}

func testJWERoundTrip(t *testing.T, keyAlg jwa.KeyEncryptionAlgorithm, contentAlg jwa.ContentEncryptionAlgorithm) {
	t.Helper()

	sk, err := pqchpke.GenerateKey()
	require.NoError(t, err, "GenerateKey")

	pk := sk.Public()

	encrypted, err := jwe.Encrypt(
		[]byte(samplePlaintext),
		jwe.WithKey(keyAlg, pk),
		jwe.WithContentEncryption(contentAlg),
	)
	require.NoError(t, err, "jwe.Encrypt")

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(keyAlg, sk))
	require.NoError(t, err, "jwe.Decrypt")

	require.Equal(t, samplePlaintext, string(decrypted), "round-trip plaintext match")
}

func TestEncryptHPKE_UnsupportedAlgorithm(t *testing.T) {
	sk, err := pqchpke.GenerateKey()
	require.NoError(t, err)

	pk := sk.Public()

	// HPKE-5-KE is an x448 ciphersuite, not one of ours. Passing it
	// to a HybridPublicKey should surface a clear error instead of
	// silently producing garbage.
	_, _, err = pk.EncryptHPKE([]byte("cek"), "HPKE-5-KE", "A256GCM")
	require.Error(t, err, "unsupported alg should be rejected")
}

func TestHybridPrivateKeyRedacted(t *testing.T) {
	// Use a fixed seed so we can also check that the seed's first few
	// bytes never appear in any formatted output — catches a future
	// regression where String()/GoString() is deleted but %v still
	// "works" because the struct happens to print empty.
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	const redacted = "pqchpke.HybridPrivateKey{redacted}"

	// Direct format verbs must all route through String()/GoString().
	// Without the methods, %+v prints {sk:... pk:... seed:[1 2 3 ...]}
	// and dumps the entire 32-byte X-Wing seed.
	require.Equal(t, redacted, sk.String())
	require.Equal(t, redacted, fmt.Sprintf("%v", sk))
	require.Equal(t, redacted, fmt.Sprintf("%+v", sk))
	require.Equal(t, redacted, fmt.Sprintf("%#v", sk))

	// Real-world leak path: a caller embeds a *HybridPrivateKey in an
	// outer struct and prints the outer struct with %+v. fmt recurses
	// through the pointer into the pointee unless the pointee has its
	// own Stringer, at which point the redacted form wins.
	outer := struct {
		Key *pqchpke.HybridPrivateKey
	}{Key: sk}
	out := fmt.Sprintf("%+v", outer)
	require.Contains(t, out, redacted, "embedded pointer should render redacted")
	require.NotContains(t, out, "seed:", "field name must not leak")
	require.NotContains(t, out, "[1 2 3 4 5 6 7 8", "seed bytes must not leak")
}
