package hpke

// NewAES256GCMAEAD returns the AES-256-GCM AEAD (HPKE AEAD ID 0x0002)
// used by HPKE-10-KE.
func NewAES256GCMAEAD() AEAD {
	return nil // TODO: stub
}

// NewChaCha20Poly1305AEAD returns the ChaCha20-Poly1305 AEAD
// (HPKE AEAD ID 0x0003) used by HPKE-11-KE.
func NewChaCha20Poly1305AEAD() AEAD {
	return nil // TODO: stub
}
