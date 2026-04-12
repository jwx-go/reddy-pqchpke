package hpke_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	circlhpke "github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem/xwing"
	"github.com/stretchr/testify/require"

	"github.com/jwx-go/reddy-pqchpke/v4/internal/hpke"
)

// TestCrossCheckAgainstCircl validates our RFC 9180 key-schedule
// transliteration against cloudflare/circl's HPKE by running a
// bidirectional interop test: circl seals → we open, and we seal →
// circl opens. If either direction fails, our labels, suite_id, or
// key-schedule sequencing has drifted from RFC 9180.
//
// The test uses the HKDF-SHA256 KDF (not the production SHAKE256),
// because circl v1.6.3 doesn't ship SHAKE256 HPKE yet (see
// cloudflare/circl#553). This is a structural cross-check: it
// validates every part of our HPKE engine *except* the KDF primitive
// itself. A label-spelling or suite_id bug that the SHAKE256
// production path shares would be caught here, because the code is
// KDF-pluggable and both paths use the same keySchedule.
//
// See docs/design.md §9 for the broader test strategy.
//
// When circl#553 lands in a released circl, delete this file —
// internal/hpke will be replaced by a thin wrapper around
// circl/hpke.NewSuite(..., KDF_SHAKE256, ...) and this cross-check
// becomes redundant.
func TestCrossCheckAgainstCircl(t *testing.T) {
	// HKDF-SHA256 cross-check suite. KEMID and AEAD match circl's
	// KEM_XWING + AEAD_AES256GCM so our hpkeSuiteID produces the same
	// 10-byte suite_id as circl uses internally.
	ourSuite := hpke.Ciphersuite{
		KEMID: 0x647a, // MLKEM768-X25519 per draft-ietf-hpke-pq
		KDF:   hpke.NewHKDFSHA256KDF(),
		AEAD:  hpke.NewAES256GCMAEAD(),
	}

	circlSuite := circlhpke.NewSuite(
		circlhpke.KEM_XWING,
		circlhpke.KDF_HKDF_SHA256,
		circlhpke.AEAD_AES256GCM,
	)

	// Fixed X-Wing key pair so the test is deterministic modulo the
	// KEM encapsulation randomness (which we don't need to pin — the
	// test verifies interop, not byte-identity).
	seed := bytes.Repeat([]byte{0x42}, 32)
	sk, pk := xwing.DeriveKeyPair(seed)

	info := []byte("JOSE-HPKE rcpt\xffA256GCM\xff")
	cek := bytes.Repeat([]byte{0x5a}, 32)

	// Direction A: circl seals, we open.
	//
	// circl runs X-Wing.Encaps internally against pk, producing an enc
	// and a shared_secret. We recover the same shared_secret by calling
	// xwing.DecapsulateTo on enc with sk. If our key schedule agrees
	// with circl's byte-for-byte, our Open can decrypt circl's Seal
	// output using that shared secret.
	sender, err := circlSuite.NewSender(pk, info)
	require.NoError(t, err, "circl NewSender")
	enc, sealer, err := sender.Setup(rand.Reader)
	require.NoError(t, err, "circl Sender.Setup")
	ctCircl, err := sealer.Seal(cek, nil)
	require.NoError(t, err, "circl Sealer.Seal")

	ssA := make([]byte, xwing.SharedKeySize)
	sk.DecapsulateTo(ssA, enc)

	recoveredA, err := hpke.Open(ourSuite, ssA, info, ctCircl)
	require.NoError(t, err, "our Open should decrypt circl's Seal output")
	require.Equal(t, cek, recoveredA, "direction A: cek round-trip")

	// Direction B: we seal, circl opens.
	//
	// We run X-Wing.Encaps ourselves with fresh randomness, feed the
	// shared secret into our internal/hpke.Seal, and pass both the
	// enc and our sealed ciphertext to circl's Receiver to decrypt.
	var encapSeed [xwing.EncapsulationSeedSize]byte
	_, err = rand.Read(encapSeed[:])
	require.NoError(t, err, "rand for encap seed")

	ctEnc := make([]byte, xwing.CiphertextSize)
	ssB := make([]byte, xwing.SharedKeySize)
	pk.EncapsulateTo(ctEnc, ssB, encapSeed[:])

	sealedOurs, err := hpke.Seal(ourSuite, ssB, info, cek)
	require.NoError(t, err, "our Seal")

	receiver, err := circlSuite.NewReceiver(sk, info)
	require.NoError(t, err, "circl NewReceiver")
	opener, err := receiver.Setup(ctEnc)
	require.NoError(t, err, "circl Receiver.Setup")
	recoveredB, err := opener.Open(sealedOurs, nil)
	require.NoError(t, err, "circl's Open should decrypt our Seal output")
	require.Equal(t, cek, recoveredB, "direction B: cek round-trip")
}
