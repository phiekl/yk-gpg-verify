<!--
Copyright 2022 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# yk-gpg-verify

A tool and related library to validate PGP keys derived from YubiKeys, and
optionally compare the public keys to YubiKey attestation certificates.

Make sure to validate the attestation certificates prior to comparison. This
can be done using [yk-attest-verify](https://github.com/joemiller/yk-attest-verify).
