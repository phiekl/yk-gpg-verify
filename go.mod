// Copyright 2022 Philip Eklöf
//
// SPDX-License-Identifier: CC0-1.0

module github.com/phiekl/yk-gpg-verify

go 1.17

replace github.com/ProtonMail/go-crypto => github.com/phiekl/go-crypto v0.0.0-20220105154729-53cd9218e3b9

require (
	github.com/ProtonMail/go-crypto v0.0.0-00010101000000-000000000000
	github.com/spf13/cobra v1.3.0
)

require (
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.0.0-20210817164053-32db794688a5 // indirect
)
