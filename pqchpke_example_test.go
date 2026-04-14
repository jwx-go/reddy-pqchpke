package pqchpke_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"

	pqchpke "github.com/jwx-go/reddy-pqchpke/v4"
)

// Example demonstrates a full JWE round-trip using the hybrid
// post-quantum HPKE-10-KE ciphersuite (X25519+ML-KEM-768, SHAKE256,
// AES-256-GCM). The hybrid key encapsulation protects the CEK against
// both classical and post-quantum attackers; a break in either
// component KEM alone does not compromise the scheme.
//
// HPKE-11-KE works the same way, substituting ChaCha20-Poly1305 for
// AES-256-GCM inside HPKE.
func Example() {
	// Generate a fresh hybrid key pair. The 32-byte seed inside sk
	// deterministically derives both the ML-KEM-768 component and the
	// X25519 component via X-Wing's ExpandDecapsulationKey.
	sk, err := pqchpke.GenerateKey()
	if err != nil {
		fmt.Println("generate key:", err)
		return
	}
	pk := sk.Public()

	plaintext := []byte("draft-reddy hybrid HPKE example payload")

	// Encrypt with the hybrid public key as the JWE recipient key.
	// jwe.Encrypt dispatches to HybridPublicKey.EncryptHPKE internally
	// because HPKE-10-KE is registered as an HPKE key encryption
	// algorithm in this module's init().
	encrypted, err := jwe.Encrypt(
		plaintext,
		jwe.WithKey(pqchpke.HPKE10(), pk),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}

	// Decrypt with the private key. jwe.Decrypt dispatches to
	// HybridPrivateKey.DecryptHPKE.
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(pqchpke.HPKE10(), sk))
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}

	fmt.Println(string(decrypted))
	// Output: draft-reddy hybrid HPKE example payload
}
