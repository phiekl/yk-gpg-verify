/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

package pgp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	pktTypePublicKey = iota + 1
	pktTypeSignature
	pktTypeUserID
)

const (
	sigTypePositiveCert = iota + 1
	sigTypeSubkeyBinding
)

// PublicKeyBundle represents the structure of a PGP public key derived from a
// YubiKey. Sig(n) is the primary key (which also has the cert capability).
// (Aut)henticate and (Enc)rypt are subkeys. UserID is a separate PGP packet,
// hence it being a separate field.
type PublicKeyBundle struct {
	Aut    *PublicKeySet
	Enc    *PublicKeySet
	Sig    *PublicKeySet
	UserID string
}

// PublicKeySet is the set of a public key and its related signature.
type PublicKeySet struct {
	PublicKey *packet.PublicKey
	Signature *packet.Signature
}

// AutValid verifies the aut public subkey's signature using the sig primary key.
func (b *PublicKeyBundle) AutValid() (bool, error) {
	err := PublicKeyVerifySubkey(b.Aut.PublicKey, b.Aut.Signature, b.Sig.PublicKey)
	if err != nil {
		return false, err
	}
	return true, err
}

// EncValid verifies the enc public subkey's signature using the sig primary key.
func (b *PublicKeyBundle) EncValid() (bool, error) {
	err := PublicKeyVerifySubkey(b.Enc.PublicKey, b.Enc.Signature, b.Sig.PublicKey)
	if err != nil {
		return false, err
	}
	return true, err
}

// SigValid verifies the public key and userid combination's self-signature.
func (b *PublicKeyBundle) SigValid() (bool, error) {
	err := PublicKeyVerify(b.Sig.PublicKey, b.Sig.Signature, b.UserID)
	if err != nil {
		return false, err
	}
	return true, err
}

// GetExpiryTime returns the public key's expiry time as defined in its signature.
func (s *PublicKeySet) GetExpiryTime() time.Time {
	sec := *(s.Signature.KeyLifetimeSecs)
	return s.PublicKey.CreationTime.Add(time.Duration(sec) * time.Second)
}

// GetPublicKeyAlgorithm returns the public key's algorithm type as text.
func (s *PublicKeySet) GetPublicKeyAlgorithm() *string {
	return PublicKeyTranslateAlgorithm(s.PublicKey.PubKeyAlgo)
}

// GetSignatureAlgorithm returns the signature's algorithm type as text.
func (s *PublicKeySet) GetSignatureAlgorithm() *string {
	return PublicKeyTranslateAlgorithm(s.Signature.PubKeyAlgo)
}

// MatchesPubKey returns true if the public key is equal to another given public key.
func (s *PublicKeySet) MatchesPubKey(key crypto.PublicKey) bool {
	return PublicKeyCompare(s.PublicKey.PublicKey, key)
}

// PublicKeyCompare returns true if both given public keys are equal.
func PublicKeyCompare(key1 crypto.PublicKey, key2 crypto.PublicKey) bool {
	switch k := key1.(type) {
	case *rsa.PublicKey:
		return k.Equal(key2)
	case *ecdsa.PublicKey:
		return k.Equal(key2)
	case *ed25519.PublicKey:
		return k.Equal(key2)
	}
	return false
}

// PublicKeyParse reads the given armored block, parsing all its PGP packets,
// while expecting the order of packets and types to conform to a PGP public
// key derived from a YubiKey. Only the Sig and UserID fields in the returned
// PublicKeyBundle are guaranteed to be non-nil.
func PublicKeyParse(block *armor.Block) (*PublicKeyBundle, error) {
	keys := make(map[[20]byte]*packet.PublicKey)
	var fingerprint [20]byte
	b := new(PublicKeyBundle)

	// Expect a primary public key as first packet.
	expectPkt := pktTypePublicKey
	expectPrimary := true
	expectSig := 0

	reader := packet.NewReader(block.Body)

	for {
		data, err := reader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed reading pgp packet: %s", err)
		}

		switch pkt := data.(type) {
		case *packet.PublicKey:
			if expectPkt != pktTypePublicKey {
				return nil, fmt.Errorf("public key packet is out-of-order (!=%d)", expectPkt)
			}

			// Expect SHA-1 fingerprints.
			if len(pkt.Fingerprint) != 20 {
				return nil, fmt.Errorf("invalid public key fingerprint length (%x)", pkt.Fingerprint)
			}
			copy(fingerprint[:], pkt.Fingerprint)
			if _, found := keys[fingerprint]; found {
				return nil, fmt.Errorf("duplicate key (%x)", fingerprint)
			}

			if pkt.IsSubkey {
				if expectPrimary {
					return nil, fmt.Errorf("expected primary key, found subkey (%x)", fingerprint)
				}
				expectPkt = pktTypeSignature
				expectSig = sigTypeSubkeyBinding
				// Don't store the pubkey packet in the bundle yet, as its usecase is
				// determined by its signature.
			} else {
				if !expectPrimary {
					return nil, fmt.Errorf("expected subkey, found primary key (%x)", fingerprint)
				}
				b.Sig = &PublicKeySet{PublicKey: pkt}
				expectPkt = pktTypeUserID
				expectSig = 0
				expectPrimary = false // there may only be a single primary key
			}

			keys[fingerprint] = pkt

		case *packet.Signature:
			if expectPkt != pktTypeSignature {
				return nil, fmt.Errorf("signature packet is out-of-order (!=%d)", expectPkt)
			}

			switch pkt.SigType {
			case packet.SigTypePositiveCert:
				// RFC4880: 0x13: Positive certification of a User ID and Public-Key packet
				if expectSig != sigTypePositiveCert {
					return nil, fmt.Errorf(
						"positive certification signature packet out-of-order (!=%d)", expectSig)
				}
				if !pkt.FlagCertify {
					/// RFC4880: 0x01 - This key may be used to certify other keys.
					return nil, fmt.Errorf("primary key missing certify capabiltiy")
				}
				if !pkt.FlagSign {
					/// RFC4880: 0x02 - This key may be used to sign data.
					return nil, fmt.Errorf("primary key missing sign capabiltiy")
				}
				b.Sig.Signature = pkt

			case packet.SigTypeSubkeyBinding:
				// RFC4880: 0x18: Subkey Binding Signature
				if expectSig != sigTypeSubkeyBinding {
					return nil, fmt.Errorf(
						"subkey binding signature packet out-of-order (!=%d)", expectSig)
				}
				if pkt.FlagAuthenticate {
					// RFC44880: 0x20 - This key may be used for authentication.
					if b.Aut != nil {
						return nil, fmt.Errorf(
							"excess subkey signature with authenticate capability (%x)", fingerprint)
					}
					b.Aut = &PublicKeySet{keys[fingerprint], pkt}

				} else if pkt.FlagEncryptCommunications && pkt.FlagEncryptStorage {
					// RFC44880: 0x04 - This key may be used to encrypt communications.
					//           0x08 - This key may be used to encrypt storage.
					if b.Enc != nil {
						return nil, fmt.Errorf(
							"excess subkey signature with encrypt capability (%x)", fingerprint)
					}
					b.Enc = &PublicKeySet{keys[fingerprint], pkt}
				} else {
					return nil, fmt.Errorf(
						"subkey signature without authenticate/encrypt capability (%x)", fingerprint)
				}

			default:
				return nil, fmt.Errorf("unknown signature packet type (%#x)", pkt.SigType)
			}
			expectPkt = pktTypePublicKey
			expectSig = 0

		case *packet.UserId:
			if expectPkt != pktTypeUserID {
				return nil, fmt.Errorf("user id packet is out-of-order (!=%d)", expectPkt)
			}
			b.UserID = pkt.Id
			expectPkt = pktTypeSignature
			expectSig = sigTypePositiveCert

		default:
			return nil, fmt.Errorf("unknown packet type (%T)", pkt)
		}
	}

	if expectPkt != pktTypePublicKey {
		return nil, fmt.Errorf("incomplete parsing, expected type not found (%d)", expectPkt)
	} else if expectPrimary {
		return nil, fmt.Errorf("incomplete parsing, no packets found")
	}

	return b, nil
}

// PublicKeyTranslateAlgorithm translates the given packet.PublicKeyAlgorithm
// into its corresponding algorithm name.
func PublicKeyTranslateAlgorithm(algo packet.PublicKeyAlgorithm) *string {
	var res string

	switch algo {
	case packet.PubKeyAlgoRSA:
		res = "rsa"
	case packet.PubKeyAlgoElGamal:
		res = "elgamal"
	case packet.PubKeyAlgoDSA:
		res = "dsa"
	case packet.PubKeyAlgoECDH:
		res = "cv25519"
	case packet.PubKeyAlgoECDSA:
		res = "ecdsa"
	case packet.PubKeyAlgoEdDSA:
		res = "ed25519"
	default:
		return nil
	}

	return &res
}

// PublicKeyVerify verifies the signature of a public key and userid combination.
func PublicKeyVerify(key *packet.PublicKey, sig *packet.Signature, userid string) error {
	if sig.SigExpired(time.Now()) {
		return fmt.Errorf("key signature has expired")
	}

	if key.KeyExpired(sig, time.Now()) {
		return fmt.Errorf("key has expired")
	}

	err := key.VerifyUserIdSignature(userid, key, sig)
	if err != nil {
		return fmt.Errorf("invalid signature for key and userid combination: %s", err)
	}

	return nil
}

// PublicKeyVerifySubkey verifies the signature of a subkey using the primary key.
func PublicKeyVerifySubkey(key *packet.PublicKey, sig *packet.Signature, issuer *packet.PublicKey) error {
	if sig.SigExpired(time.Now()) {
		return fmt.Errorf("subkey signature has expired")
	}

	if key.KeyExpired(sig, time.Now()) {
		return fmt.Errorf("subkey has expired")
	}

	if !bytes.Equal(sig.IssuerFingerprint, issuer.Fingerprint) {
		return fmt.Errorf(
			"mismatching issuer of subkey signature (%x, expected: %x)",
			sig.IssuerFingerprint, issuer.Fingerprint,
		)
	}

	err := issuer.VerifyKeySignature(key, sig)
	if err != nil {
		return fmt.Errorf("invalid signature for subkey: %s", err)
	}

	return nil
}
