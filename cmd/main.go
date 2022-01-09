/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

package cmd

import (
	"crypto"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/phiekl/yk-gpg-verify/pkg/misc"
	"github.com/phiekl/yk-gpg-verify/pkg/pgp"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "yk-gpg-verify [flags] pgp_public_key_file",
	Args:         cobra.ExactArgs(1),
	RunE:         main,
	SilenceUsage: true,
}

// Execute runs the argument parsing and the rest of the configured program.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringP(
		"revocation-file",
		"r",
		"",
		"revocation signature file",
	)
	rootCmd.Flags().StringP(
		"sig-att-file",
		"s",
		"",
		"sig attestation certificate file",
	)
	rootCmd.Flags().StringP(
		"aut-att-file",
		"a",
		"",
		"aut attestation certificate file",
	)
	rootCmd.Flags().StringP(
		"enc-att-file",
		"e",
		"",
		"enc attestation certificate file",
	)
}

type result struct {
	Data    resultData   `json:"data"`
	Error   *resultError `json:"error"`
	Success bool         `json:"success"`
}

type resultData struct {
	Aut        *resultKey `json:"authenticate"`
	Enc        *resultKey `json:"encrypt"`
	Revocation *resultRev `json:"revocation"`
	Sig        *resultKey `json:"sign"`
	UserID     *string    `json:"user_id"`
}

type resultKey struct {
	PublicKey *resultPublicKey `json:"public_key"`
	Signature *resultSignature `json:"signature"`
}

type resultRev struct {
	Signature resultSignature `json:"signature"`
}

type resultPublicKey struct {
	Algorithm   *string     `json:"algorithm"`
	BitLength   *uint16     `json:"bit_length"`
	CreateTime  time.Time   `json:"create_time"`
	ExpiryTime  time.Time   `json:"expiry_time"`
	Fingerprint string      `json:"fingerprint"`
	Matching    interface{} `json:"matching"` // nullable bool
	Version     int         `json:"version"`
	Subkey      bool        `json:"subkey"`
}

type resultSignature struct {
	Algorithm  *string     `json:"algorithm"`
	CreateTime time.Time   `json:"create_time"`
	Issuer     string      `json:"issuer"`
	Valid      interface{} `json:"valid"` // nullable bool
	Version    int         `json:"version"`
}

type resultError struct {
	Messages []string
}

func (e *resultError) Add(msg string) {
	e.Messages = append(e.Messages, msg)
}

func (e *resultError) MarshalJSON() ([]byte, error) {
	if e.Messages == nil {
		// Make sure JSON ends up as an empty array, not null.
		return json.Marshal(make([]string, 0))
	}
	return json.Marshal(e.Messages)
}

func finalize(res *result, error *resultError) error {
	res.Error = error
	if len(error.Messages) == 0 {
		res.Success = true
	}

	output, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", output)

	if !res.Success {
		os.Exit(1)
	}

	return nil
}

func makeresultKey(set *pgp.PublicKeySet) *resultKey {
	bitLength, _ := set.PublicKey.BitLength()

	p := resultPublicKey{
		Algorithm:   set.GetPublicKeyAlgorithm(),
		BitLength:   &bitLength,
		CreateTime:  set.PublicKey.CreationTime,
		ExpiryTime:  set.GetExpiryTime(),
		Fingerprint: fmt.Sprintf("%x", set.PublicKey.Fingerprint),
		Subkey:      set.PublicKey.IsSubkey,
		Version:     set.PublicKey.Version,
	}

	s := makeresultSignature(set.Signature)

	return &resultKey{
		PublicKey: &p,
		Signature: &s,
	}
}
func makeresultSignature(sig *packet.Signature) resultSignature {
	return resultSignature{
		Algorithm:  pgp.PublicKeyTranslateAlgorithm(sig.PubKeyAlgo),
		CreateTime: sig.CreationTime,
		Issuer:     fmt.Sprintf("%x", sig.IssuerFingerprint),
		Version:    sig.Version,
	}
}

func main(cmd *cobra.Command, args []string) error {
	var autPublicKey crypto.PublicKey
	var encPublicKey crypto.PublicKey
	var sigPublicKey crypto.PublicKey
	var revocationCert *armor.Block
	var revocationSignature *packet.Signature

	pgpFile := args[0]

	autFile, err := cmd.Flags().GetString("aut-att-file")
	if err != nil {
		return err
	}
	encFile, err := cmd.Flags().GetString("enc-att-file")
	if err != nil {
		return err
	}
	revocationFile, err := cmd.Flags().GetString("revocation-file")
	if err != nil {
		return err
	}
	sigFile, err := cmd.Flags().GetString("sig-att-file")
	if err != nil {
		return err
	}

	pgpPublicKey, err := pgp.DearmorPublicKeyFile(pgpFile)
	if err != nil {
		return fmt.Errorf("failed loading PGP public key file: %s", err)
	}
	if revocationFile != "" {
		revocationCert, err = pgp.DearmorPublicKeyFile(revocationFile)
		if err != nil {
			return fmt.Errorf("failed loading PGP revocation certificate file: %s", err)
		}
	}

	if autFile != "" {
		autPublicKey, err = misc.GetCertFilePublicKey(autFile)
		if err != nil {
			return fmt.Errorf("failed loading AUT attestation certificate file: %s", err)
		}
	}
	if encFile != "" {
		encPublicKey, err = misc.GetCertFilePublicKey(encFile)
		if err != nil {
			return fmt.Errorf("failed loading ENC attestation certificate file: %s", err)
		}
	}
	if sigFile != "" {
		sigPublicKey, err = misc.GetCertFilePublicKey(sigFile)
		if err != nil {
			return fmt.Errorf("failed loading SIG attestation certificate file: %s", err)
		}
	}

	res, error := &result{}, &resultError{}

	bundle, err := pgp.PublicKeyParse(pgpPublicKey)
	if err != nil {
		error.Add(err.Error())
		return finalize(res, error)
	}

	res.Data.UserID = &bundle.UserID

	res.Data.Sig = makeresultKey(bundle.Sig)
	if res.Data.Sig.Signature.Valid, err = bundle.SigValid(); err != nil {
		error.Add("SIG PGP: " + err.Error())
	}
	if sigPublicKey != nil {
		res.Data.Sig.PublicKey.Matching = bundle.Sig.MatchesPubKey(sigPublicKey)
		if res.Data.Sig.PublicKey.Matching == false {
			error.Add("SIG PGP key not matching attestation certificate key")
		}
	}

	if bundle.Aut != nil {
		res.Data.Aut = makeresultKey(bundle.Aut)
		if res.Data.Aut.Signature.Valid, err = bundle.AutValid(); err != nil {
			error.Add("AUT PGP: " + err.Error())
		}
		if autPublicKey != nil {
			res.Data.Aut.PublicKey.Matching = bundle.Aut.MatchesPubKey(autPublicKey)
			if res.Data.Aut.PublicKey.Matching == false {
				error.Add("AUT PGP key not matching attestation certificate key")
			}
		}
	} else {
		error.Add("no AUT PGP key found with authenticate capability")
	}

	if bundle.Enc != nil {
		res.Data.Enc = makeresultKey(bundle.Enc)
		if res.Data.Enc.Signature.Valid, err = bundle.EncValid(); err != nil {
			error.Add("ENC PGP: " + err.Error())
		}
		if encPublicKey != nil {
			res.Data.Enc.PublicKey.Matching = bundle.Enc.MatchesPubKey(encPublicKey)
			if res.Data.Enc.PublicKey.Matching == false {
				error.Add("ENC PGP key not matching attestation certificate key")
			}
		}
	} else {
		error.Add("No ENC PGP key found with encrypt capability")
	}

	if revocationFile != "" {
		revocationSignature, err = pgp.RevocationCertVerify(revocationCert, bundle.Sig.PublicKey)
		if err != nil {
			error.Add("revocation PGP: " + err.Error())
		}
		res.Data.Revocation = &resultRev{makeresultSignature(revocationSignature)}
	}

	return finalize(res, error)
}
