package hpke

// KEM identifier for MLKEM768-X25519 from the IANA HPKE KEM registry
// (registered by draft-ietf-hpke-pq).
const KEMIDMLKEM768X25519 uint16 = 0x647a

// SuiteHPKE10KE is the ciphersuite for `HPKE-10-KE`:
// MLKEM768-X25519 + SHAKE256 + AES-256-GCM.
func SuiteHPKE10KE() Ciphersuite {
	return Ciphersuite{
		KEMID: KEMIDMLKEM768X25519,
		KDF:   NewSHAKE256KDF(),
		AEAD:  NewAES256GCMAEAD(),
	}
}

// SuiteHPKE11KE is the ciphersuite for `HPKE-11-KE`:
// MLKEM768-X25519 + SHAKE256 + ChaCha20-Poly1305.
func SuiteHPKE11KE() Ciphersuite {
	return Ciphersuite{
		KEMID: KEMIDMLKEM768X25519,
		KDF:   NewSHAKE256KDF(),
		AEAD:  NewChaCha20Poly1305AEAD(),
	}
}
