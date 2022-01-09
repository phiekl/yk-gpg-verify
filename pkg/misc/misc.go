/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

package misc

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// GetCertFilePublicKey opens given filename, reads it as a PEM certificate file
// and returns the public key within.
func GetCertFilePublicKey(file string) (crypto.PublicKey, error) {
	fileData, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	pemData, _ := pem.Decode(fileData)
	if pemData == nil {
		return nil, fmt.Errorf("failed decoding file as PEM certificate")
	}

	certData, err := x509.ParseCertificate(pemData.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := certData.PublicKey.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid or no public key")
	}

	return pubKey, nil
}
