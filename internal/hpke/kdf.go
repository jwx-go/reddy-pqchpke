package hpke

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// shake256KDF implements the one-stage SHAKE256 HPKE KDF per
// draft-ietf-hpke-pq §5. Derive absorbs ikm and squeezes L bytes via
// SHAKE256. Extract/Expand are not applicable and panic if called —
// keySchedule is expected to gate them with IsTwoStage.
type shake256KDF struct{}

func (shake256KDF) Nh() int          { return 64 }
func (shake256KDF) IsTwoStage() bool { return false }
func (shake256KDF) ID() uint16       { return 0x0011 }

func (shake256KDF) Extract(salt, ikm []byte) []byte {
	panic("pqchpke/internal/hpke: shake256 is a one-stage KDF; Extract is not defined")
}

func (shake256KDF) Expand(prk, info []byte, L int) []byte {
	panic("pqchpke/internal/hpke: shake256 is a one-stage KDF; Expand is not defined")
}

func (shake256KDF) Derive(ikm []byte, L int) []byte {
	out := make([]byte, L)
	sha3.ShakeSum256(out, ikm)
	return out
}

// NewSHAKE256KDF returns the SHAKE256-based HPKE KDF used by HPKE-10-KE
// and HPKE-11-KE in production.
func NewSHAKE256KDF() KDF {
	return shake256KDF{}
}

// hkdfSHA256KDF implements the two-stage HKDF-SHA256 HPKE KDF per
// RFC 9180. Used only for the cross-check test against circl/hpke;
// never used in the production HPKE-10-KE / HPKE-11-KE path.
type hkdfSHA256KDF struct{}

func (hkdfSHA256KDF) Nh() int          { return 32 }
func (hkdfSHA256KDF) IsTwoStage() bool { return true }
func (hkdfSHA256KDF) ID() uint16       { return 0x0001 }

func (hkdfSHA256KDF) Extract(salt, ikm []byte) []byte {
	return hkdf.Extract(sha256.New, ikm, salt)
}

func (hkdfSHA256KDF) Expand(prk, info []byte, L int) []byte {
	out := make([]byte, L)
	rd := hkdf.Expand(sha256.New, prk, info)
	if _, err := io.ReadFull(rd, out); err != nil {
		panic(err)
	}
	return out
}

func (hkdfSHA256KDF) Derive(ikm []byte, L int) []byte {
	panic("pqchpke/internal/hpke: hkdf-sha256 is a two-stage KDF; Derive is not defined")
}

// NewHKDFSHA256KDF returns the HKDF-SHA256-based HPKE KDF. This KDF
// exists only to enable the byte-for-byte cross-check against circl's
// X-Wing + HKDF-SHA256 HPKE in tests (see internal/hpke/hpke_test.go
// and docs/design.md §9). It is never used in production.
func NewHKDFSHA256KDF() KDF {
	return hkdfSHA256KDF{}
}
