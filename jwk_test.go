package pqchpke_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"

	pqchpke "github.com/jwx-go/reddy-pqchpke/v4"
)

// TestJWKImport_HybridPrivateKey imports a raw hybrid private key into a
// JWK and verifies the resulting AKP JWK has the expected kty, alg, pub,
// and priv fields.
func TestJWKImport_HybridPrivateKey(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	k, err := jwk.Import[jwk.Key](sk)
	require.NoError(t, err, "jwk.Import(*HybridPrivateKey)")

	require.Equal(t, jwa.AKP(), k.KeyType(), "kty")

	alg, ok := k.Algorithm()
	require.True(t, ok, "alg should be set")
	require.Equal(t, pqchpke.HPKE10KE, alg.String(), "default alg is HPKE-10-KE")

	privKey, ok := k.(jwk.AKPPrivateKey)
	require.True(t, ok, "imported key should be AKPPrivateKey")

	pub, ok := privKey.Pub()
	require.True(t, ok)
	require.Len(t, pub, pqchpke.PublicKeySize)

	priv, ok := privKey.Priv()
	require.True(t, ok)
	require.Equal(t, sampleSeed[:], priv, "priv should be the 32-byte seed")
}

// TestJWKImport_HybridPublicKey imports a raw hybrid public key.
func TestJWKImport_HybridPublicKey(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)
	pk := sk.Public()

	k, err := jwk.Import[jwk.Key](pk)
	require.NoError(t, err, "jwk.Import(*HybridPublicKey)")

	require.Equal(t, jwa.AKP(), k.KeyType())

	pubKey, ok := k.(jwk.AKPPublicKey)
	require.True(t, ok, "imported key should be AKPPublicKey")

	pubBytes, ok := pubKey.Pub()
	require.True(t, ok)
	require.Equal(t, pk.Bytes(), pubBytes, "pub bytes round-trip")
}

// TestJWKRoundTrip_HPKE10KE_PrivateKey marshals an imported hybrid
// private key to JSON, parses it back, exports to raw, and verifies the
// seed and public bytes match the original.
func TestJWKRoundTrip_HPKE10KE_PrivateKey(t *testing.T) {
	testJWKRoundTripPrivateKey(t, pqchpke.HPKE10KE)
}

// TestJWKRoundTrip_HPKE11KE_PrivateKey verifies the alg=HPKE-11-KE path
// through the JWK exporter resolves to the correct raw type.
func TestJWKRoundTrip_HPKE11KE_PrivateKey(t *testing.T) {
	testJWKRoundTripPrivateKey(t, pqchpke.HPKE11KE)
}

func testJWKRoundTripPrivateKey(t *testing.T, alg string) {
	t.Helper()

	original, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	k, err := jwk.Import[jwk.Key](original)
	require.NoError(t, err)

	// Override alg if the test targets HPKE-11-KE (the importer defaults
	// to HPKE-10-KE). This is the documented way to pick a non-default
	// ciphersuite for a hybrid key.
	algVal, _ := jwa.KeyAlgorithmFrom(alg)
	require.NoError(t, k.Set(jwk.AlgorithmKey, algVal))

	encoded, err := json.Marshal(k)
	require.NoError(t, err, "json.Marshal(jwk.Key)")

	parsed, err := jwk.ParseKeyAs[jwk.Key](encoded)
	require.NoError(t, err, "jwk.ParseKey")

	exported, err := jwk.Export[*pqchpke.HybridPrivateKey](parsed)
	require.NoError(t, err, "jwk.Export[*HybridPrivateKey]")
	require.Equal(t, original.Seed(), exported.Seed(), "seed round-trip")
	require.Equal(t, original.Public().Bytes(), exported.Public().Bytes(), "derived pub round-trip")
}

// TestJWKRoundTrip_PublicKey verifies the public-key JWK path.
func TestJWKRoundTrip_PublicKey(t *testing.T) {
	original, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)
	originalPub := original.Public()

	k, err := jwk.Import[jwk.Key](originalPub)
	require.NoError(t, err)

	encoded, err := json.Marshal(k)
	require.NoError(t, err)

	parsed, err := jwk.ParseKeyAs[jwk.Key](encoded)
	require.NoError(t, err)

	exported, err := jwk.Export[*pqchpke.HybridPublicKey](parsed)
	require.NoError(t, err, "jwk.Export[*HybridPublicKey]")
	require.Equal(t, originalPub.Bytes(), exported.Bytes(), "pub round-trip")
}

// TestJWKImport_WithAlgorithm_HPKE11KE verifies that a hybrid key
// tagged with HPKE-11-KE via WithAlgorithm imports with that alg,
// instead of the HPKE-10-KE default.
func TestJWKImport_WithAlgorithm_HPKE11KE(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	tagged := sk.WithAlgorithm(pqchpke.HPKE11())

	k, err := jwk.Import[jwk.Key](tagged)
	require.NoError(t, err)

	alg, ok := k.Algorithm()
	require.True(t, ok)
	require.Equal(t, pqchpke.HPKE11KE, alg.String(), "alg follows WithAlgorithm")

	// Public key path.
	pk := tagged.Public()
	kp, err := jwk.Import[jwk.Key](pk)
	require.NoError(t, err)
	alg, ok = kp.Algorithm()
	require.True(t, ok)
	require.Equal(t, pqchpke.HPKE11KE, alg.String(), "Public() propagates alg")
}

// TestJWKImport_WithAlgorithm_Invalid rejects a non-HPKE alg rather
// than silently coercing it — the whole point of alg binding is to
// fail loudly on mismatches.
func TestJWKImport_WithAlgorithm_Invalid(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	rsaOAEP, ok := jwa.LookupKeyEncryptionAlgorithm("RSA-OAEP")
	require.True(t, ok, "RSA-OAEP is a builtin jwa alg")

	bad := sk.WithAlgorithm(rsaOAEP)
	_, err = jwk.Import[jwk.Key](bad)
	require.Error(t, err, "non-HPKE alg must be rejected at import")

	_, err = jwk.Import[jwk.Key](bad.Public())
	require.Error(t, err, "non-HPKE alg must be rejected at import (public)")
}

// TestHybridKey_Algorithm_ZeroValue reports an empty alg on a freshly
// derived key — the importer default (HPKE-10-KE) is applied at
// Import time, not recorded on the raw wrapper.
func TestHybridKey_Algorithm_ZeroValue(t *testing.T) {
	sk, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	require.Equal(t, "", sk.Algorithm().String())
	require.Equal(t, "", sk.Public().Algorithm().String())

	tagged := sk.WithAlgorithm(pqchpke.HPKE11())
	require.Equal(t, pqchpke.HPKE11KE, tagged.Algorithm().String())
	require.Equal(t, pqchpke.HPKE11KE, tagged.Public().Algorithm().String(),
		"Public() must propagate alg from the private wrapper")

	// Original untouched: WithAlgorithm returns a copy.
	require.Equal(t, "", sk.Algorithm().String(),
		"WithAlgorithm must not mutate the receiver")
}

// TestJWKExport_MismatchedPubPriv rejects an AKP JWK whose pub field
// doesn't match the key derived from priv. This guards against
// malformed or tampered JWKs.
func TestJWKExport_MismatchedPubPriv(t *testing.T) {
	// Build an AKP JWK by hand with a valid priv and a deliberately
	// wrong pub. The exporter's derived-vs-claimed check should reject it.
	original, err := pqchpke.PrivateKeyFromSeed(sampleSeed[:])
	require.NoError(t, err)

	k, err := jwk.Import[jwk.Key](original)
	require.NoError(t, err)

	// Replace pub with garbage of the right length.
	junk := make([]byte, pqchpke.PublicKeySize)
	for i := range junk {
		junk[i] = 0xff
	}
	require.NoError(t, k.Set(jwk.AKPPubKey, junk))

	_, err = jwk.Export[*pqchpke.HybridPrivateKey](k)
	require.Error(t, err, "mismatched pub/priv should be rejected on export")
}
