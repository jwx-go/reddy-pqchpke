package pqchpke

import (
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

func init() {
	// Register JWK importers so jwk.Import(*HybridPublicKey) and
	// jwk.Import(*HybridPrivateKey) produce an AKP JWK.
	jwk.RegisterKeyImporter(importHybridPublicKey)
	jwk.RegisterKeyImporter(importHybridPrivateKey)

	// Register exporters keyed by AKP KeyKind + alg, so jwk.Export[*HybridPublicKey](k)
	// and jwk.Export[*HybridPrivateKey](k) on an AKP JWK whose alg is HPKE-10-KE /
	// HPKE-11-KE produce the corresponding raw type.
	jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE10KE), jwk.KeyExportFunc(exportHybrid))
	jwk.RegisterKeyExporter(jwk.KeyKind("AKP:"+HPKE11KE), jwk.KeyExportFunc(exportHybrid))
}

func importHybridPublicKey(src *HybridPublicKey) (jwk.Key, error) {
	_ = src
	return nil, errors.New("pqchpke: importHybridPublicKey not implemented")
}

func importHybridPrivateKey(src *HybridPrivateKey) (jwk.Key, error) {
	_ = src
	return nil, errors.New("pqchpke: importHybridPrivateKey not implemented")
}

func exportHybrid(key jwk.Key, _ any) (any, error) {
	_ = key
	return nil, errors.New("pqchpke: exportHybrid not implemented")
}
