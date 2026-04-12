// Package hpke implements the RFC 9180 HPKE key schedule for the
// MLKEM768-X25519 + SHAKE256 ciphersuites used by draft-reddy-cose-jose-pqc-hybrid-hpke.
//
// This is a hand-rolled implementation because Go stdlib crypto/hpke is
// HKDF-only and cloudflare/circl's released hpke package is also HKDF-only.
// The draft requires SHAKE256 as the HPKE KDF, which neither library supports
// as of 2026-04.
//
// The key schedule is KDF-pluggable so tests can instantiate it with
// HKDF-SHA256 and compare byte-for-byte against circl/hpke as a structural
// cross-check. Production code uses the SHAKE256 variant.
//
// TODO(circl#553): https://github.com/cloudflare/circl/pull/553 adds
// SHAKE256 KDF support to circl's HPKE. When it merges and lands in a
// release, delete this package and use circl/hpke directly.
package hpke

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// versionLabel is the HPKE-v1 prefix used inside LabeledExtract / LabeledExpand /
// LabeledDerive per RFC 9180 §4 and draft-ietf-hpke-pq §5.
const versionLabel = "HPKE-v1"

// modeBase is the RFC 9180 mode identifier for base (non-PSK, non-authenticated)
// HPKE. This module only implements mode_base.
const modeBase byte = 0x00

// KDF is the HPKE KDF interface. Two-stage KDFs (HKDF family) implement
// Extract + Expand. One-stage KDFs (SHAKE256 per draft-ietf-hpke-pq §5)
// implement Derive instead. The keySchedule branches on IsTwoStage.
type KDF interface {
	// Nh returns the natural output length of the KDF's Extract or Derive
	// function in bytes. SHAKE256 = 64, HKDF-SHA256 = 32.
	Nh() int

	// IsTwoStage reports whether this KDF follows RFC 9180's two-step
	// Extract+Expand structure (true for HKDF-*) or the draft-ietf-hpke-pq
	// one-stage Derive structure (false for SHAKE256).
	IsTwoStage() bool

	// Extract performs the HKDF Extract step. Only called for two-stage
	// KDFs. One-stage KDFs may panic here.
	Extract(salt, ikm []byte) []byte

	// Expand performs the HKDF Expand step. Only called for two-stage
	// KDFs. One-stage KDFs may panic here.
	Expand(prk, info []byte, L int) []byte

	// Derive performs the one-stage KDF operation:
	//   SHAKE<bits>(M = ikm, d = 8*L)
	// per draft-ietf-hpke-pq §5. Only called for one-stage KDFs.
	// Two-stage KDFs may panic here.
	Derive(ikm []byte, L int) []byte

	// ID returns the IANA HPKE KDF identifier used when building suite_id
	// bytes. SHAKE256 = 0x0011, HKDF-SHA256 = 0x0001.
	ID() uint16
}

// AEAD is the HPKE AEAD interface.
type AEAD interface {
	// Nk returns the AEAD key length in bytes.
	Nk() int

	// Nn returns the AEAD nonce length in bytes.
	Nn() int

	// Nt returns the AEAD tag length in bytes.
	Nt() int

	// New returns a cipher.AEAD initialized with the given key.
	New(key []byte) (cipher.AEAD, error)

	// ID returns the IANA HPKE AEAD identifier. AES-128-GCM = 0x0001,
	// AES-256-GCM = 0x0002, ChaCha20-Poly1305 = 0x0003.
	ID() uint16
}

// Ciphersuite bundles a KEM id (numeric, from the IANA HPKE KEM registry)
// with a KDF and AEAD. The KEM itself is not part of this struct because
// HPKE key-schedule only cares about the KEM's ID (for suite_id) and the
// 32-byte shared secret it produces. Callers run the KEM separately.
type Ciphersuite struct {
	KEMID uint16
	KDF   KDF
	AEAD  AEAD
}

// Seal performs HPKE-KE sealing for mode_base. Given the post-KEM shared
// secret, the JOSE HPKE info bytes (see draft-ietf-jose-hpke-encrypt §6.1),
// and the CEK to seal, it returns the AEAD-sealed ciphertext. This is
// intentionally narrow: it does not run the KEM itself, and it does not
// derive or expose an exporter secret.
//
// For HPKE-KE single-shot sealing the sequence number is always 0, so the
// per-message nonce equals the base nonce. AAD is always empty per
// draft-ietf-jose-hpke-encrypt §6 bullet 4.
func Seal(suite Ciphersuite, sharedSecret, info, cek []byte) ([]byte, error) {
	key, baseNonce, err := keySchedule(suite, sharedSecret, info)
	if err != nil {
		return nil, err
	}
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, fmt.Errorf("pqchpke/internal/hpke: new AEAD: %w", err)
	}
	return aead.Seal(nil, baseNonce, cek, nil), nil
}

// Open performs HPKE-KE opening for mode_base. Returns the plaintext CEK,
// or an AEAD authentication error if the shared secret, info bytes, or
// sealed ciphertext have been tampered with.
func Open(suite Ciphersuite, sharedSecret, info, sealed []byte) ([]byte, error) {
	key, baseNonce, err := keySchedule(suite, sharedSecret, info)
	if err != nil {
		return nil, err
	}
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, fmt.Errorf("pqchpke/internal/hpke: new AEAD: %w", err)
	}
	cek, err := aead.Open(nil, baseNonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("pqchpke/internal/hpke: AEAD open: %w", err)
	}
	return cek, nil
}

// keySchedule is the RFC 9180 §5.1 mode_base key schedule, transliterated
// to support both two-stage KDFs (Extract+Expand, per RFC 9180) and
// one-stage KDFs (Derive, per draft-ietf-hpke-pq §5). For mode_base we
// always use empty psk and psk_id.
//
// This function is the canonical source of the label bytes
// ("psk_id_hash", "info_hash", "secret", "key", "base_nonce") — do not
// change them without re-reading RFC 9180 §5.1.
func keySchedule(suite Ciphersuite, sharedSecret, info []byte) (key, baseNonce []byte, err error) {
	if suite.KDF == nil {
		return nil, nil, fmt.Errorf("pqchpke/internal/hpke: suite KDF is nil")
	}
	if suite.AEAD == nil {
		return nil, nil, fmt.Errorf("pqchpke/internal/hpke: suite AEAD is nil")
	}

	Nk := suite.AEAD.Nk()
	Nn := suite.AEAD.Nn()
	Nh := suite.KDF.Nh()

	suiteID := hpkeSuiteID(suite)

	if suite.KDF.IsTwoStage() {
		pskIDHash := labeledExtract(suite.KDF, suiteID, nil, []byte("psk_id_hash"), nil)
		infoHash := labeledExtract(suite.KDF, suiteID, nil, []byte("info_hash"), info)
		context := concat([]byte{modeBase}, pskIDHash, infoHash)

		secret := labeledExtract(suite.KDF, suiteID, sharedSecret, []byte("secret"), nil)
		key = labeledExpand(suite.KDF, suiteID, secret, []byte("key"), context, Nk)
		baseNonce = labeledExpand(suite.KDF, suiteID, secret, []byte("base_nonce"), context, Nn)
		// exporter_secret would be labeledExpand(secret, "exp", context, Nh) —
		// we don't use it in HPKE-KE single-shot sealing.
		_ = Nh
		return key, baseNonce, nil
	}

	// One-stage (SHAKE256) per draft-ietf-hpke-pq §5. Matches the
	// bas/hpke-pq branch of cloudflare/circl (circl#553).
	secrets := concat(
		lengthPrefixed(nil), // psk (empty for mode_base)
		lengthPrefixed(sharedSecret),
	)
	context := concat(
		[]byte{modeBase},
		lengthPrefixed(nil), // psk_id (empty for mode_base)
		lengthPrefixed(info),
	)
	combined := labeledDerive(suite.KDF, suiteID, secrets, []byte("secret"), context, Nk+Nn+Nh)
	key = combined[:Nk]
	baseNonce = combined[Nk : Nk+Nn]
	// exporter_secret = combined[Nk+Nn:]  // unused for HPKE-KE
	return key, baseNonce, nil
}

// hpkeSuiteID builds the HPKE suite ID bytes per RFC 9180 §5.1:
//
//	"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
//
// For HPKE-10-KE: "HPKE" || 0x647a || 0x0011 || 0x0002.
// For HPKE-11-KE: "HPKE" || 0x647a || 0x0011 || 0x0003.
func hpkeSuiteID(suite Ciphersuite) []byte {
	id := make([]byte, 10)
	copy(id[0:4], "HPKE")
	binary.BigEndian.PutUint16(id[4:6], suite.KEMID)
	binary.BigEndian.PutUint16(id[6:8], suite.KDF.ID())
	binary.BigEndian.PutUint16(id[8:10], suite.AEAD.ID())
	return id
}

// labeledExtract performs RFC 9180 §4 LabeledExtract.
func labeledExtract(kdf KDF, suiteID, salt, label, ikm []byte) []byte {
	labeledIKM := concat([]byte(versionLabel), suiteID, label, ikm)
	return kdf.Extract(salt, labeledIKM)
}

// labeledExpand performs RFC 9180 §4 LabeledExpand.
func labeledExpand(kdf KDF, suiteID, prk, label, info []byte, L int) []byte {
	var packedL [2]byte
	binary.BigEndian.PutUint16(packedL[:], uint16(L))
	labeledInfo := concat(packedL[:], []byte(versionLabel), suiteID, label, info)
	return kdf.Expand(prk, labeledInfo, L)
}

// labeledDerive performs the one-stage labeled derive per
// draft-ietf-hpke-pq §5, matching the circl#553 construction:
//
//	SHAKE256(
//	    ikm || "HPKE-v1" || suite_id ||
//	    I2OSP(len(label), 2) || label || I2OSP(L, 2) || context,
//	    L
//	)
func labeledDerive(kdf KDF, suiteID, ikm, label, context []byte, L int) []byte {
	var labelLen, packedL [2]byte
	binary.BigEndian.PutUint16(labelLen[:], uint16(len(label)))
	binary.BigEndian.PutUint16(packedL[:], uint16(L))
	labeledIKM := concat(ikm, []byte(versionLabel), suiteID, labelLen[:], label, packedL[:], context)
	return kdf.Derive(labeledIKM, L)
}

// lengthPrefixed prepends a 2-byte big-endian length to x.
func lengthPrefixed(x []byte) []byte {
	out := make([]byte, 2+len(x))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(x)))
	copy(out[2:], x)
	return out
}

// concat concatenates all the byte slices.
func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
