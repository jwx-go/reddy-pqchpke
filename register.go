package pqchpke

import (
	"fmt"

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
	panicOnRegistrationError(jwa.RegisterKeyEncryptionAlgorithm(hpke10ke))
	panicOnRegistrationError(jwa.RegisterKeyEncryptionAlgorithm(hpke11ke))

	// Mark these as HPKE algorithms so jwebb.IsHPKE returns true, routing
	// them through the existing HPKE-KE dispatch in jwe.Encrypt / jwe.Decrypt.
	panicOnRegistrationError(jwebb.RegisterHPKEAlgorithm(HPKE10KE))
	panicOnRegistrationError(jwebb.RegisterHPKEAlgorithm(HPKE11KE))
}

// panicOnRegistrationError converts a non-nil error returned by a jwx
// Register* call during init() into an import-time panic. The rule
// (documented in jwx's internals.md) is that a failed Register* leaves
// the extension unusable, so we surface it immediately instead of
// letting the program continue in a broken state.
func panicOnRegistrationError(err error) {
	if err != nil {
		panic(fmt.Sprintf("jwx-go/reddy-pqchpke: registration failed: %s", err))
	}
}
