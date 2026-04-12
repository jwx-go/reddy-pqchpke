package hpke_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jwx-go/reddy-pqchpke/v4/internal/hpke"
)

// sampleSharedSecret is a fixed 32-byte value we pretend came out of the
// KEM. internal/hpke operates on post-KEM shared secrets and doesn't care
// where they come from, so synthetic input is fine here.
var sampleSharedSecret = bytes.Repeat([]byte{0xab}, 32)

// sampleInfo mimics the JOSE-HPKE info bytes that the top-level package
// would pass through. Byte content is not checked here — only that
// Seal/Open sees the same bytes on both sides.
var sampleInfo = []byte("JOSE-HPKE rcpt\xffA256GCM\xff")

var sampleCEK = []byte("0123456789abcdef0123456789abcdef") // 32 bytes

func TestSealOpenRoundTrip_HPKE10KE(t *testing.T) {
	testSealOpenRoundTrip(t, hpke.SuiteHPKE10KE())
}

func TestSealOpenRoundTrip_HPKE11KE(t *testing.T) {
	testSealOpenRoundTrip(t, hpke.SuiteHPKE11KE())
}

func testSealOpenRoundTrip(t *testing.T, suite hpke.Ciphersuite) {
	t.Helper()

	sealed, err := hpke.Seal(suite, sampleSharedSecret, sampleInfo, sampleCEK)
	require.NoError(t, err, "Seal")

	opened, err := hpke.Open(suite, sampleSharedSecret, sampleInfo, sealed)
	require.NoError(t, err, "Open")

	require.Equal(t, sampleCEK, opened, "round-trip plaintext match")
}

func TestOpen_TamperedCiphertext(t *testing.T) {
	suite := hpke.SuiteHPKE10KE()

	sealed, err := hpke.Seal(suite, sampleSharedSecret, sampleInfo, sampleCEK)
	require.NoError(t, err, "Seal")
	require.NotEmpty(t, sealed)

	// Flip one byte in the middle of the sealed ciphertext — Open must
	// reject (AEAD tag check should fail).
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)/2] ^= 0xff

	_, err = hpke.Open(suite, sampleSharedSecret, sampleInfo, tampered)
	require.Error(t, err, "tampered ciphertext should fail to open")
}

func TestOpen_WrongSharedSecret(t *testing.T) {
	suite := hpke.SuiteHPKE10KE()

	sealed, err := hpke.Seal(suite, sampleSharedSecret, sampleInfo, sampleCEK)
	require.NoError(t, err)

	wrong := bytes.Repeat([]byte{0xcd}, 32)
	_, err = hpke.Open(suite, wrong, sampleInfo, sealed)
	require.Error(t, err, "wrong shared secret should fail to open")
}

// TestCrossCheckAgainstCircl validates our KDF-pluggable key schedule
// against circl/hpke. The test instantiates our Seal with HKDF-SHA256
// (via our hpke.NewHKDFSHA256KDF) and compares the output against
// circl's X-Wing + HKDF-SHA256 + AES-256-GCM HPKE sealing. Structural
// check only — does not validate the SHAKE256 primitive.
//
// See docs/design.md §9 for why this check matters.
func TestCrossCheckAgainstCircl(t *testing.T) {
	// TODO(internal/hpke impl): cross-check against
	// github.com/cloudflare/circl/hpke with KEM_XWING + KDF_HKDF_SHA256
	// + AEAD_AES256GCM. This requires figuring out how to inject a
	// pre-computed shared_secret into circl's HPKE key schedule so we
	// can compare byte-for-byte. Deferred to internal/hpke
	// implementation phase.
	t.Skip("cross-check deferred until internal/hpke implementation")
}
