package pqchpke

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
)

func init() {
	panicOnRegistrationError(jwk.RegisterKeyImporter(importHybridPublicKey))
	panicOnRegistrationError(jwk.RegisterKeyImporter(importHybridPrivateKey))

	// Register exporters keyed by KeyKind("AKP:<alg>"). jwk.Export uses
	// the key's KeyKind to pick an exporter, and jwk/akp.go's
	// akpKeyKind() namespaces AKP keys by their alg field, so a JWK
	// with alg=HPKE-10-KE ends up at KeyKind "AKP:HPKE-10-KE".
	panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE10KE), jwk.KeyExportFunc(exportHybrid)))
	panicOnRegistrationError(jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE11KE), jwk.KeyExportFunc(exportHybrid)))
}

// resolveImportAlg picks the alg to tag an imported AKP JWK with. The
// raw HybridPublicKey/HybridPrivateKey types are alg-agnostic, so the
// binding comes from WithAlgorithm on the wrapper. When unset the
// default is HPKE-10-KE; any alg outside the HPKE-10-KE / HPKE-11-KE
// pair is rejected rather than silently coerced.
func resolveImportAlg(alg jwa.KeyEncryptionAlgorithm) (jwa.KeyAlgorithm, error) {
	switch alg.String() {
	case "":
		out, _ := jwa.KeyAlgorithmFrom(HPKE10KE)
		return out, nil
	case HPKE10KE, HPKE11KE:
		out, _ := jwa.KeyAlgorithmFrom(alg.String())
		return out, nil
	default:
		return nil, fmt.Errorf("pqchpke: cannot import hybrid key with alg %q: only %s and %s are supported", alg.String(), HPKE10KE, HPKE11KE)
	}
}

func importHybridPublicKey(src *HybridPublicKey) (jwk.Key, error) {
	alg, err := resolveImportAlg(src.alg)
	if err != nil {
		return nil, err
	}
	key, err := jwkunsafe.NewPublicKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf("pqchpke: new AKP public key: %w", err)
	}
	if err := key.Set(jwk.AKPPubKey, src.Bytes()); err != nil {
		return nil, fmt.Errorf("pqchpke: set pub: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("pqchpke: set alg: %w", err)
	}
	return key, nil
}

func importHybridPrivateKey(src *HybridPrivateKey) (jwk.Key, error) {
	alg, err := resolveImportAlg(src.alg)
	if err != nil {
		return nil, err
	}
	key, err := jwkunsafe.NewKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf("pqchpke: new AKP key: %w", err)
	}
	if err := key.Set(jwk.AKPPubKey, src.Public().Bytes()); err != nil {
		return nil, fmt.Errorf("pqchpke: set pub: %w", err)
	}
	if err := key.Set(jwk.AKPPrivKey, src.Seed()); err != nil {
		return nil, fmt.Errorf("pqchpke: set priv: %w", err)
	}
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("pqchpke: set alg: %w", err)
	}
	return key, nil
}

// exportHybrid converts an AKP JWK whose alg is HPKE-10-KE or HPKE-11-KE
// back to a raw *HybridPublicKey or *HybridPrivateKey.
func exportHybrid(key jwk.Key, _ any) (any, error) {
	switch k := key.(type) {
	case jwk.AKPPrivateKey:
		pubBytes, ok := k.Pub()
		if !ok {
			return nil, fmt.Errorf(`pqchpke: missing "pub" field`)
		}
		priv, ok := k.Priv()
		if !ok {
			return nil, fmt.Errorf(`pqchpke: missing "priv" field`)
		}
		sk, err := PrivateKeyFromSeed(priv)
		if err != nil {
			return nil, err
		}
		// Cross-check: the public key derived from the seed must match
		// the `pub` field bytes. If they disagree, the JWK is malformed
		// or came from a different key family.
		if !bytes.Equal(sk.Public().Bytes(), pubBytes) {
			return nil, fmt.Errorf(`pqchpke: "pub" field does not match key derived from "priv"`)
		}
		return sk, nil
	case jwk.AKPPublicKey:
		pubBytes, ok := k.Pub()
		if !ok {
			return nil, fmt.Errorf(`pqchpke: missing "pub" field`)
		}
		return PublicKeyFromBytes(pubBytes)
	default:
		return nil, jwk.ContinueError()
	}
}
