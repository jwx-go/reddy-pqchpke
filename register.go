package pqchpke

import (
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe/jwebb"
)

var (
	hpke10ke = jwa.NewKeyEncryptionAlgorithm(HPKE10KE)
	hpke11ke = jwa.NewKeyEncryptionAlgorithm(HPKE11KE)
)

// HPKE10 returns the HPKE-10-KE key encryption algorithm.
func HPKE10() jwa.KeyEncryptionAlgorithm { return hpke10ke }

// HPKE11 returns the HPKE-11-KE key encryption algorithm.
func HPKE11() jwa.KeyEncryptionAlgorithm { return hpke11ke }

func init() {
	// Register the algorithm identifiers so jwa.KeyAlgorithmFrom resolves them.
	jwa.RegisterKeyEncryptionAlgorithm(hpke10ke)
	jwa.RegisterKeyEncryptionAlgorithm(hpke11ke)

	// Mark these as HPKE algorithms so jwebb.IsHPKE returns true, routing
	// them through the existing HPKE-KE dispatch in jwe.Encrypt / jwe.Decrypt.
	jwebb.RegisterHPKEAlgorithm(HPKE10KE)
	jwebb.RegisterHPKEAlgorithm(HPKE11KE)
}
