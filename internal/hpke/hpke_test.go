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

// The circl cross-check test lives in circl_cross_test.go so it can be
// deleted in a single file-level rm when cloudflare/circl#553 merges and
// drops this whole internal/hpke package.
