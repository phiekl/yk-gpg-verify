/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

package pgp

import (
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// RevocationCertVerify reads the given armored block, expects that the first
// PGP packet is a signature, which is returned.
func RevocationCertVerify(cert *armor.Block, key *packet.PublicKey) (*packet.Signature, error) {
	reader := packet.NewReader(cert.Body)

	pkt, err := reader.Next()
	if err != nil {
		return nil, fmt.Errorf("failed reading PGP packet: %s", err)
	}

	signature, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("block did not begin with a signature packet")
	}

	return signature, key.VerifyRevocationSignature(signature)
}
