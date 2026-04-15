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
// The same X-Wing keypair can be used with either HPKE-10-KE or HPKE-11-KE.
// When imported into a jwk.Key with jwk.Import, the resulting AKP JWK is
// tagged with alg=HPKE-10-KE by default. To bind an imported key to
// HPKE-11-KE instead, call WithAlgorithm before importing:
//
//	key, err := jwk.Import[jwk.Key](pk.WithAlgorithm(pqchpke.HPKE11()))
//
// Only HPKE-10-KE and HPKE-11-KE are accepted; any other algorithm is
// rejected at import time.
type HybridPublicKey struct {
	pk  *xwing.PublicKey
	alg jwa.KeyEncryptionAlgorithm
}

// HybridPrivateKey is a raw key type that holds a hybrid X25519+ML-KEM-768
// private key. Implements jwebb.HPKEKeyDecrypter.
//
// See HybridPublicKey for the alg-binding rules that apply when importing
// this key into a jwk.Key. To bind to HPKE-11-KE at import time:
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
// key encryption algorithm. The returned key behaves identically for
// direct EncryptHPKE calls; the binding is consulted at jwk.Import
// time so the resulting JWK carries the right alg field.
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
// key encryption algorithm. See HybridPublicKey.WithAlgorithm.
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

// Seed returns a copy of the 32-byte X-Wing seed backing this private
// key. This is the value that goes into the AKP JWK `priv` field.
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
	suite, err := suiteForAlg(alg)
	if err != nil {
		return nil, nil, err
	}

	// X-Wing encapsulation consumes 64 bytes of randomness — this drives
	// both the ML-KEM-768 encapsulation and the ephemeral X25519 scalar.
	var encapSeed [xwing.EncapsulationSeedSize]byte
	if _, err := rand.Read(encapSeed[:]); err != nil {
		return nil, nil, fmt.Errorf("pqchpke: encap rand: %w", err)
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
