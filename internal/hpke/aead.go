package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// aes256GCMAEAD is HPKE AEAD ID 0x0002: AES-256-GCM with 12-byte nonce.
type aes256GCMAEAD struct{}

func (aes256GCMAEAD) Nk() int    { return 32 }
func (aes256GCMAEAD) Nn() int    { return 12 }
func (aes256GCMAEAD) Nt() int    { return 16 }
func (aes256GCMAEAD) ID() uint16 { return 0x0002 }

func (aes256GCMAEAD) New(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("pqchpke/internal/hpke: aes-256-gcm key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pqchpke/internal/hpke: aes-256-gcm new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// NewAES256GCMAEAD returns the AES-256-GCM AEAD used by HPKE-10-KE.
func NewAES256GCMAEAD() AEAD {
	return aes256GCMAEAD{}
}

// chacha20Poly1305AEAD is HPKE AEAD ID 0x0003: ChaCha20-Poly1305 with
// 12-byte nonce.
type chacha20Poly1305AEAD struct{}

func (chacha20Poly1305AEAD) Nk() int    { return 32 }
func (chacha20Poly1305AEAD) Nn() int    { return 12 }
func (chacha20Poly1305AEAD) Nt() int    { return 16 }
func (chacha20Poly1305AEAD) ID() uint16 { return 0x0003 }

func (chacha20Poly1305AEAD) New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

// NewChaCha20Poly1305AEAD returns the ChaCha20-Poly1305 AEAD used by HPKE-11-KE.
func NewChaCha20Poly1305AEAD() AEAD {
	return chacha20Poly1305AEAD{}
}
