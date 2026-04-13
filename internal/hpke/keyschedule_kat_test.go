package hpke

// Pinned-byte Known Answer Test (KAT) for the HPKE key schedule.
//
// Regression for review finding XCUT-009 / EXT-012: prior to this test the
// production keySchedule function had ZERO external cross-check — only
// self-consistency via Seal→Open round-trips. A consistent bug on both
// sides (e.g. wrong label string, wrong length encoding, swapped key/nonce
// slice indices) would pass round-trip tests undetected because both Seal
// and Open call the same buggy keySchedule.
//
// This KAT pins the exact output bytes for a fixed input tuple so that
// any change to the one-stage SHAKE256 derive construction in
// labeledDerive / keySchedule (per draft-ietf-hpke-pq §5 and the
// circl#553 construction) will be caught immediately.
//
// If this test fails after an intentional change to the key schedule,
// re-derive the pinned values against an independent implementation
// (e.g. cloudflare/circl once #553 lands) BEFORE updating the constants.

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeyScheduleKAT_HPKE10KE(t *testing.T) {
	// Fixed input tuple:
	//   suite        = HPKE-10-KE (MLKEM768-X25519 + SHAKE256 + AES-256-GCM)
	//   sharedSecret = 0xab repeated 32 times (synthetic post-KEM secret)
	//   info         = "JOSE-HPKE rcpt" || 0xff || "A256GCM" || 0xff
	//                  This matches the shape used in hpke_test.go's
	//                  sampleInfo, mimicking the JOSE-HPKE info bytes the
	//                  top-level package passes through (see
	//                  draft-ietf-jose-hpke-encrypt §6.1).
	suite := SuiteHPKE10KE()
	sharedSecret := bytes.Repeat([]byte{0xab}, 32)
	info := []byte("JOSE-HPKE rcpt\xffA256GCM\xff")

	key, baseNonce, err := keySchedule(suite, sharedSecret, info)
	require.NoError(t, err, "keySchedule")

	// Pinned expected values. AES-256-GCM: Nk=32, Nn=12.
	wantKey, err := hex.DecodeString("57b5aedbc389ec4851cbe3f7c28dc1406d84d8644f7d48a03edf4239c761caa6")
	require.NoError(t, err)
	wantNonce, err := hex.DecodeString("8e91df4d9768c2a882ac37ee")
	require.NoError(t, err)

	require.Equal(t, hex.EncodeToString(wantKey), hex.EncodeToString(key), "AEAD key bytes")
	require.Equal(t, hex.EncodeToString(wantNonce), hex.EncodeToString(baseNonce), "base nonce bytes")
}
