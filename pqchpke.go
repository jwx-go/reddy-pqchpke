package pqchpke

import (
	"errors"

	"github.com/cloudflare/circl/kem/xwing"
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
type HybridPublicKey struct {
	pk *xwing.PublicKey
}

// HybridPrivateKey is a raw key type that holds a hybrid X25519+ML-KEM-768
// private key seed. Implements jwebb.HPKEKeyDecrypter.
type HybridPrivateKey struct {
	sk *xwing.PrivateKey
	// seed caches the 32-byte seed used to derive sk, because circl's
	// DeriveKeyPair doesn't expose it directly and we need it for AKP
	// JWK export.
	seed [PrivateKeySize]byte
}

// GenerateKey produces a fresh hybrid key pair using crypto/rand.
func GenerateKey() (*HybridPrivateKey, error) {
	return nil, errors.New("pqchpke: GenerateKey not implemented")
}

// PrivateKeyFromSeed constructs a HybridPrivateKey from a 32-byte seed
// (typically the AKP JWK `priv` field).
func PrivateKeyFromSeed(seed []byte) (*HybridPrivateKey, error) {
	_ = seed
	return nil, errors.New("pqchpke: PrivateKeyFromSeed not implemented")
}

// PublicKeyFromBytes constructs a HybridPublicKey from its 1216-byte
// packed form (typically the AKP JWK `pub` field).
func PublicKeyFromBytes(pub []byte) (*HybridPublicKey, error) {
	_ = pub
	return nil, errors.New("pqchpke: PublicKeyFromBytes not implemented")
}

// Public returns the public key corresponding to this private key.
func (sk *HybridPrivateKey) Public() *HybridPublicKey {
	return nil
}

// Seed returns a copy of the 32-byte X-Wing seed backing this private
// key. Matches AKP JWK `priv` byte-for-byte.
func (sk *HybridPrivateKey) Seed() []byte {
	return nil
}

// Bytes returns the 1216-byte packed form of this public key. Matches
// AKP JWK `pub` byte-for-byte.
func (pk *HybridPublicKey) Bytes() []byte {
	return nil
}

// EncryptHPKE implements jwebb.HPKEKeyEncrypter. It runs X-Wing
// encapsulation against this public key, then seals the given CEK with
// the HPKE key schedule selected by alg (HPKE-10-KE or HPKE-11-KE), with
// calg bound into the info parameter per draft-ietf-jose-hpke-encrypt §6.1.
//
// Returns the HPKE-sealed CEK and the 1120-byte encapsulated key that
// becomes the `ek` JWE header parameter.
func (pk *HybridPublicKey) EncryptHPKE(cek []byte, alg, calg string) (sealedCEK, enc []byte, err error) {
	_ = cek
	_ = alg
	_ = calg
	return nil, nil, errors.New("pqchpke: EncryptHPKE not implemented")
}

// DecryptHPKE implements jwebb.HPKEKeyDecrypter.
func (sk *HybridPrivateKey) DecryptHPKE(sealedCEK []byte, alg, calg string, enc []byte) ([]byte, error) {
	_ = sealedCEK
	_ = alg
	_ = calg
	_ = enc
	return nil, errors.New("pqchpke: DecryptHPKE not implemented")
}
