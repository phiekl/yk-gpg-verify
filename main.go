/*
 * Copyright 2022 Philip Eklöf
 *
 * SPDX-License-Identifier: MIT
 */

// Package yk-gpg-verify verifies a PGP key derived from a YubiKey.
package main

import (
	"github.com/phiekl/yk-gpg-verify/cmd"
)

func main() {
	cmd.Execute()
}
