package pqchpke_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"

	pqchpke "github.com/jwx-go/reddy-pqchpke/v4"
)

// FuzzEncryptAndDecryptHPKE10 round-trips arbitrary payloads through
// jwe.Encrypt / jwe.Decrypt using a hybrid X25519+ML-KEM-768 key pair
// bound to HPKE-10-KE. The key pair is generated once in the seed stage
// since GenerateKey is expensive relative to the fuzz loop.
func FuzzEncryptAndDecryptHPKE10(f *testing.F) {
	f.Add([]byte("Hello, post-quantum world!"))
	f.Add([]byte(""))
	f.Add([]byte(`{"iss":"test"}`))

	sk, err := pqchpke.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	pk := sk.Public()

	f.Fuzz(func(t *testing.T, payload []byte) {
		encrypted, err := jwe.Encrypt(payload, jwe.WithKey(pqchpke.HPKE10(), pk))
		require.NoError(t, err)

		decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(pqchpke.HPKE10(), sk))
		require.NoError(t, err)
		// Compare as strings: jwe.Decrypt returns a nil slice for a
		// zero-length plaintext rather than an empty non-nil slice, and
		// that distinction isn't semantically meaningful here.
		require.Equal(t, string(payload), string(decrypted))
	})
}

// FuzzDecryptMalformed feeds arbitrary bytes straight into jwe.Decrypt
// with a valid hybrid private key. Garbage input must be rejected with
// an error, never a panic. The two genuine seeds (compact and JSON
// serialized) are expected to decrypt successfully; when they — or any
// other input the fuzzer discovers — do decrypt, the resulting
// plaintext must equal the original seed payload. A mismatch there
// would mean the decrypted bytes were forged or tampered with without
// being rejected, which is a forgery/malleability bug. The key pair and
// the genuine JWEs are built once in the seed stage.
func FuzzDecryptMalformed(f *testing.F) {
	sk, err := pqchpke.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	pk := sk.Public()

	seedPayload := []byte("seed payload")

	compact, err := jwe.Encrypt(seedPayload, jwe.WithKey(pqchpke.HPKE10(), pk))
	if err != nil {
		f.Fatal(err)
	}

	jsonSerialized, err := jwe.Encrypt(seedPayload, jwe.WithKey(pqchpke.HPKE10(), pk), jwe.WithJSON())
	if err != nil {
		f.Fatal(err)
	}

	f.Add(compact)
	f.Add(jsonSerialized)
	f.Add([]byte(""))
	f.Add([]byte("not-a-jwe"))

	// Truncated variant: drop the last quarter of the compact JWE.
	if n := len(compact); n > 4 {
		f.Add(compact[:n-n/4])
	}

	// Bit-flipped variant: flip a bit in the middle of the compact JWE.
	if len(compact) > 0 {
		flipped := append([]byte(nil), compact...)
		flipped[len(flipped)/2] ^= 0xff
		f.Add(flipped)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decrypted, err := jwe.Decrypt(data, jwe.WithKey(pqchpke.HPKE10(), sk))
		if err != nil {
			return
		}
		require.Equal(t, seedPayload, decrypted, "decrypted plaintext must match the original seed payload; a mismatch means forged or malleable ciphertext was accepted")
	})
}

// FuzzParseHybridJWK checks that the hybrid AKP JWK importer/parser
// never panics on arbitrary input, and that a successfully parsed key
// can be marshaled and re-parsed without panicking either. The seed
// includes the JSON of a genuine hybrid JWK exported from a generated
// key.
func FuzzParseHybridJWK(f *testing.F) {
	sk, err := pqchpke.GenerateKey()
	if err != nil {
		f.Fatal(err)
	}

	k, err := jwk.Import[jwk.Key](sk)
	if err != nil {
		f.Fatal(err)
	}

	genuine, err := json.Marshal(k)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(genuine)
	f.Add([]byte(""))
	f.Add([]byte("not-json"))

	// Truncated variant: drop the last quarter of the genuine JWK JSON.
	if n := len(genuine); n > 4 {
		f.Add(genuine[:n-n/4])
	}

	// Mutated variant: flip a bit in the middle of the genuine JWK JSON.
	if len(genuine) > 0 {
		mutated := append([]byte(nil), genuine...)
		mutated[len(mutated)/2] ^= 0xff
		f.Add(mutated)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		parsed, err := jwk.ParseKey(data)
		if err != nil {
			return
		}

		buf, err := json.Marshal(parsed)
		if err != nil {
			return
		}

		_, _ = jwk.ParseKey(buf)
	})
}
