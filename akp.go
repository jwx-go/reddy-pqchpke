package pqchpke

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwk/jwkunsafe"
)

func init() {
	// Register jwk.Import handlers: *HybridPublicKey / *HybridPrivateKey
	// → AKP JWK. Because these raw types are alg-agnostic (the same
	// HybridPublicKey can be used with either HPKE-10-KE or HPKE-11-KE),
	// the importer defaults `alg` to HPKE-10-KE. Users who want
	// HPKE-11-KE can override via key.Set(jwk.AlgorithmKey, ...) after
	// import.
	jwk.RegisterKeyImporter(importHybridPublicKey)
	jwk.RegisterKeyImporter(importHybridPrivateKey)

	// Register exporters keyed by KeyKind("AKP:<alg>"). jwk.Export uses
	// the key's KeyKind to pick an exporter, and jwk/akp.go's
	// akpKeyKind() namespaces AKP keys by their alg field, so a JWK
	// with alg=HPKE-10-KE ends up at KeyKind "AKP:HPKE-10-KE".
	jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE10KE), jwk.KeyExportFunc(exportHybrid))
	jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE11KE), jwk.KeyExportFunc(exportHybrid))
}

func importHybridPublicKey(src *HybridPublicKey) (jwk.Key, error) {
	key, err := jwkunsafe.NewPublicKey(jwa.AKP())
	if err != nil {
		return nil, fmt.Errorf("pqchpke: new AKP public key: %w", err)
	}
	if err := key.Set(jwk.AKPPubKey, src.Bytes()); err != nil {
		return nil, fmt.Errorf("pqchpke: set pub: %w", err)
	}
	alg, _ := jwa.KeyAlgorithmFrom(HPKE10KE)
	if err := key.Set(jwk.AlgorithmKey, alg); err != nil {
		return nil, fmt.Errorf("pqchpke: set alg: %w", err)
	}
	return key, nil
}

func importHybridPrivateKey(src *HybridPrivateKey) (jwk.Key, error) {
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
	alg, _ := jwa.KeyAlgorithmFrom(HPKE10KE)
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

