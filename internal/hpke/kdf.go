package hpke

// NewSHAKE256KDF returns the SHAKE256-based HPKE KDF per
// draft-ietf-hpke-pq §5. This is the production KDF for HPKE-10-KE and
// HPKE-11-KE.
func NewSHAKE256KDF() KDF {
	return nil // TODO: stub
}

// NewHKDFSHA256KDF returns the HKDF-SHA256-based HPKE KDF per RFC 9180.
// Used only for cross-validation tests against circl/hpke.
// This is never used in the production path.
func NewHKDFSHA256KDF() KDF {
	return nil // TODO: stub
}
