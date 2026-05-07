package pqchpke

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/lestrrat-go/jwx/v4/jwa"

	"github.com/jwx-go/reddy-pqchpke/v4/internal/hpke"
)

// Algorithm identifiers from draft-reddy-cose-jose-pqc-hybrid-hpke §9.1.
const (
	// HPKE10KE is MLKEM768-X25519 + SHAKE256 + AES-256-GCM in key-encryption mode.
	HPKE10KE = "HPKE-10-KE"

	// HPKE11KE is MLKEM768-X25519 + SHAKE256 + ChaCha20-Poly1305 in key-encryption mode.
	HPKE11KE = "HPKE-11-KE"
)

// Wire-format constants from draft-connolly-cfrg-xwing-kem §7 (via
// draft-ietf-hpke-pq for the HPKE KEM registration).
const (
	// PublicKeySize is the byte length of a packed X-Wing public key
	// (pk_M || pk_X): 1184 + 32 = 1216 bytes. Matches AKP JWK `pub`.
	PublicKeySize = 1216

	// PrivateKeySize is the byte length of an X-Wing private key seed.
	// X-Wing derives both the ML-KEM seed and the X25519 scalar from
	// this single 32-byte seed. Matches AKP JWK `priv`.
	PrivateKeySize = 32

	// EncapsulatedKeySize is the byte length of the HPKE encapsulated
	// key (ct_M || ct_X): 1088 + 32 = 1120 bytes.
	EncapsulatedKeySize = 1120

	// SharedKeySize is the byte length of the shared secret produced by
	// X-Wing encapsulation/decapsulation.
	SharedKeySize = 32
)

// ErrUnsupportedAlgorithm is returned when an alg string outside the
// set this module implements is passed in.
var ErrUnsupportedAlgorithm = errors.New("pqchpke: unsupported algorithm")

// HybridPublicKey is a raw key type that holds a hybrid X25519+ML-KEM-768
// public key (X-Wing encoding). It implements jwebb.HPKEKeyEncrypter so
// jwe.Encrypt routes HPKE-10-KE / HPKE-11-KE operations through this type.
//
// The same X-Wing keypair can be used with either HPKE-10-KE or
// HPKE-11-KE. When imported into a jwk.Key with jwk.Import, the
// resulting AKP JWK is tagged with alg=HPKE-10-KE by default. To bind
// an imported key to HPKE-11-KE instead, call WithAlgorithm before
// importing:
//
//	key, err := jwk.Import[jwk.Key](pk.WithAlgorithm(pqchpke.HPKE11()))
//
// Only HPKE-10-KE and HPKE-11-KE are accepted at import; any other
// algorithm is rejected.
//
// # Don't forget to bind
//
// A user who intends HPKE-11-KE but forgets to call WithAlgorithm
// gets a JWK whose "alg" field claims HPKE-10-KE — the import default.
// The mismatch surfaces at the next use, not silently:
//
//   - jwe.Encrypt with this JWK and jwe.WithKey(HPKE11(), key)
//     reaches EncryptHPKE with alg="HPKE-11-KE" but a wrapper bound
//     to HPKE-10-KE. EncryptHPKE returns
//     `pqchpke: alg "HPKE-11-KE" does not match key binding
//     "HPKE-10-KE" (set via WithAlgorithm)` rather than silently
//     producing an HPKE-10-KE wire artifact under an HPKE-11-KE
//     intent.
//
//   - DecryptHPKE applies the same gate symmetrically.
//
// So the worst case for a forgotten WithAlgorithm is a JWK whose
// on-disk "alg" field is wrong, plus a clear runtime error the next
// time it's used. To avoid the round trip, set the binding at import
// time.
type HybridPublicKey struct {
	pk  *xwing.PublicKey
	alg jwa.KeyEncryptionAlgorithm
}

// HybridPrivateKey is a raw key type that holds a hybrid X25519+ML-KEM-768
// private key. Implements jwebb.HPKEKeyDecrypter.
//
// See HybridPublicKey for the alg-binding rules and the don't-forget-
// to-bind discussion that apply when importing this key into a
// jwk.Key. To bind to HPKE-11-KE at import time:
//
//	key, err := jwk.Import[jwk.Key](sk.WithAlgorithm(pqchpke.HPKE11()))
type HybridPrivateKey struct {
	sk *xwing.PrivateKey
	pk *xwing.PublicKey
	// seed is the 32-byte X-Wing seed this key was derived from. Kept
	// so Seed() can round-trip it without re-deriving from sk. X-Wing's
	// private key IS the seed (PrivateKeySize = SeedSize = 32), but
	// circl doesn't expose the seed directly from *PrivateKey.
	seed [PrivateKeySize]byte
	alg  jwa.KeyEncryptionAlgorithm
}

// Algorithm returns the key encryption algorithm this key is bound to,
// or the zero value if no binding was set. The zero value means "use
// the importer default" — currently HPKE-10-KE.
func (pk *HybridPublicKey) Algorithm() jwa.KeyEncryptionAlgorithm {
	return pk.alg
}

// WithAlgorithm returns a shallow copy of this key bound to the given
// key encryption algorithm. The binding is enforced at two boundaries:
//
//   - jwk.Import — the resulting AKP JWK carries the bound alg in its
//     "alg" field rather than the HPKE-10-KE default.
//   - EncryptHPKE — the alg argument must match the binding. A
//     mismatched alg is rejected; a bound key cannot silently encrypt
//     under a different ciphersuite than the caller intended.
//
// An unbound key (zero-value alg) is unconstrained at runtime: any
// registered HPKE alg is accepted.
//
// The receiver is not mutated.
func (pk *HybridPublicKey) WithAlgorithm(alg jwa.KeyEncryptionAlgorithm) *HybridPublicKey {
	clone := *pk
	clone.alg = alg
	return &clone
}

// Algorithm returns the key encryption algorithm this key is bound to,
// or the zero value if no binding was set.
func (sk *HybridPrivateKey) Algorithm() jwa.KeyEncryptionAlgorithm {
	return sk.alg
}

// WithAlgorithm returns a shallow copy of this key bound to the given
// key encryption algorithm. The binding is enforced at jwk.Import (JWK
// "alg" field) and at DecryptHPKE (alg argument must match). An
// unbound key is unconstrained at runtime. See
// HybridPublicKey.WithAlgorithm for the full discussion.
func (sk *HybridPrivateKey) WithAlgorithm(alg jwa.KeyEncryptionAlgorithm) *HybridPrivateKey {
	clone := *sk
	clone.alg = alg
	return &clone
}

// GenerateKey produces a fresh hybrid key pair using crypto/rand.
func GenerateKey() (*HybridPrivateKey, error) {
	var seed [PrivateKeySize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, fmt.Errorf("pqchpke: generate seed: %w", err)
	}
	return PrivateKeyFromSeed(seed[:])
}

// PrivateKeyFromSeed constructs a HybridPrivateKey from a 32-byte seed,
// typically read from an AKP JWK `priv` field.
func PrivateKeyFromSeed(seed []byte) (*HybridPrivateKey, error) {
	if len(seed) != PrivateKeySize {
		return nil, fmt.Errorf("pqchpke: seed must be %d bytes, got %d", PrivateKeySize, len(seed))
	}
	sk, pk := xwing.DeriveKeyPair(seed)
	priv := &HybridPrivateKey{sk: sk, pk: pk}
	copy(priv.seed[:], seed)
	return priv, nil
}

// PublicKeyFromBytes constructs a HybridPublicKey from its 1216-byte
// packed form, typically read from an AKP JWK `pub` field.
func PublicKeyFromBytes(pub []byte) (*HybridPublicKey, error) {
	if len(pub) != PublicKeySize {
		return nil, fmt.Errorf("pqchpke: public key must be %d bytes, got %d", PublicKeySize, len(pub))
	}
	var pk xwing.PublicKey
	if err := pk.Unpack(pub); err != nil {
		return nil, fmt.Errorf("pqchpke: invalid public key: %w", err)
	}
	return &HybridPublicKey{pk: &pk}, nil
}

// Public returns the public key corresponding to this private key.
// The alg binding, if any, is propagated onto the returned public key.
func (sk *HybridPrivateKey) Public() *HybridPublicKey {
	return &HybridPublicKey{pk: sk.pk, alg: sk.alg}
}

// Seed returns a fresh copy of the 32-byte X-Wing seed backing this
// private key. This is the value that goes into the AKP JWK `priv`
// field.
//
// The returned slice is newly allocated and independent of the
// receiver's internal storage. Callers that need to zeroize the seed
// after use are responsible for wiping the returned slice themselves;
// the receiver's own copy is not affected. Importing a *HybridPrivateKey
// via jwk.Import similarly stores the seed bytes inside the resulting
// jwk.Key, so a typical import flow leaves at least two live copies on
// the heap. For an X-Wing hybrid key the seed is the only secret — it
// derives both the ML-KEM-768 and the X25519 components — so every
// live copy is equally sensitive.
func (sk *HybridPrivateKey) Seed() []byte {
	out := make([]byte, PrivateKeySize)
	copy(out, sk.seed[:])
	return out
}

// String redacts the seed so accidental %v / %+v logging of a
// HybridPrivateKey cannot leak the 32-byte X-Wing seed. For a
// post-quantum hybrid key the seed is the only secret (X-Wing derives
// both the ML-KEM and X25519 components from it), so a single %+v in a
// panic log or debug print would be a total compromise.
func (sk *HybridPrivateKey) String() string {
	return "pqchpke.HybridPrivateKey{redacted}"
}

// GoString does the same for %#v.
func (sk *HybridPrivateKey) GoString() string {
	return "pqchpke.HybridPrivateKey{redacted}"
}

// Bytes returns the 1216-byte packed form of this public key. This is
// the value that goes into the AKP JWK `pub` field.
func (pk *HybridPublicKey) Bytes() []byte {
	out := make([]byte, PublicKeySize)
	pk.pk.Pack(out)
	return out
}

// EncryptHPKE implements jwebb.HPKEKeyEncrypter. It runs X-Wing
// encapsulation against this public key, then seals the given CEK with
// the HPKE key schedule selected by alg (HPKE-10-KE or HPKE-11-KE), with
// calg bound into the info parameter per draft-ietf-jose-hpke-encrypt §6.1.
//
// Returns the HPKE-sealed CEK and the 1120-byte encapsulated key that
// becomes the `ek` JWE header parameter.
func (pk *HybridPublicKey) EncryptHPKE(cek []byte, alg, calg string) (sealedCEK, enc []byte, err error) {
	// Enforce the wrapper's alg binding (set via WithAlgorithm). An
	// unbound key (zero-value alg) accepts any registered HPKE alg;
	// a bound key rejects mismatched alg values rather than silently
	// encrypting under a different ciphersuite than the caller
	// intended.
	if want := pk.alg.String(); want != "" && want != alg {
		return nil, nil, fmt.Errorf("pqchpke: alg %q does not match key binding %q (set via WithAlgorithm)", alg, want)
	}

	// Draw the encap randomness first and zeroize on exit. Any future
	// refactor that reorders statements here must still delete the read
	// to reach EncapsulateTo with a zero seed — which would be obvious.
	// X-Wing encapsulation consumes 64 bytes of randomness driving both
	// the ML-KEM-768 encapsulation and the ephemeral X25519 scalar.
	var encapSeed [xwing.EncapsulationSeedSize]byte
	if _, err := rand.Read(encapSeed[:]); err != nil {
		return nil, nil, fmt.Errorf("pqchpke: encap rand: %w", err)
	}
	defer clear(encapSeed[:])

	suite, err := suiteForAlg(alg)
	if err != nil {
		return nil, nil, err
	}

	ct := make([]byte, xwing.CiphertextSize)
	ss := make([]byte, xwing.SharedKeySize)
	pk.pk.EncapsulateTo(ct, ss, encapSeed[:])

	info := hpkeKEInfo(calg)
	sealedCEK, err = hpke.Seal(suite, ss, info, cek)
	if err != nil {
		return nil, nil, fmt.Errorf("pqchpke: hpke seal: %w", err)
	}
	return sealedCEK, ct, nil
}

// DecryptHPKE implements jwebb.HPKEKeyDecrypter.
func (sk *HybridPrivateKey) DecryptHPKE(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error) {
	// Enforce the wrapper's alg binding — see EncryptHPKE for the
	// rationale and the unbound-key fall-through.
	if want := sk.alg.String(); want != "" && want != alg {
		return nil, fmt.Errorf("pqchpke: alg %q does not match key binding %q (set via WithAlgorithm)", alg, want)
	}

	suite, err := suiteForAlg(alg)
	if err != nil {
		return nil, err
	}
	if len(enc) != EncapsulatedKeySize {
		return nil, fmt.Errorf("pqchpke: encapsulated key must be %d bytes, got %d", EncapsulatedKeySize, len(enc))
	}

	ss := make([]byte, xwing.SharedKeySize)
	sk.sk.DecapsulateTo(ss, enc)

	info := hpkeKEInfo(calg)
	cek, err := hpke.Open(suite, ss, info, sealedCEK)
	if err != nil {
		return nil, fmt.Errorf("pqchpke: hpke open: %w", err)
	}
	return cek, nil
}

// suiteForAlg returns the internal HPKE ciphersuite for the given alg id.
func suiteForAlg(alg string) (hpke.Ciphersuite, error) {
	switch alg {
	case HPKE10KE:
		return hpke.SuiteHPKE10KE(), nil
	case HPKE11KE:
		return hpke.SuiteHPKE11KE(), nil
	default:
		return hpke.Ciphersuite{}, fmt.Errorf("%w: %s", ErrUnsupportedAlgorithm, alg)
	}
}

// hpkeKEInfo builds the HPKE info bytes per draft-ietf-jose-hpke-encrypt §6.1:
//
//	Recipient_structure = "JOSE-HPKE rcpt" || 0xff || enc_value || 0xff
func hpkeKEInfo(calg string) []byte {
	prefix := []byte("JOSE-HPKE rcpt")
	info := make([]byte, 0, len(prefix)+1+len(calg)+1)
	info = append(info, prefix...)
	info = append(info, 0xff)
	info = append(info, calg...)
	info = append(info, 0xff)
	return info
}
