/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

package pgp

import (
	"fmt"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// DearmorPublicKeyFile opens given filename and returns the decoding of its
// ascii armoring, while ensuring that it is of public key type.
func DearmorPublicKeyFile(file string) (*armor.Block, error) {
	fileHandle, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	dec, err := armor.Decode(fileHandle)
	if err != nil {
		return nil, fmt.Errorf("failed dearmoring: %s", err)
	}

	if dec.Type != openpgp.PublicKeyType {
		return nil, fmt.Errorf("not a public key (%s)", dec.Type)
	}

	return dec, nil
}
