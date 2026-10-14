// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package pgpkeys

import (
	"bytes"
	"errors"
)

// ErrNotSupported is returned by every PGP operation on js/wasm: the OpenPGP
// implementation (ProtonMail/go-crypto and cloudflare/circl) is excluded from
// this build, so init, rekey, rotate and generate-root requests that carry
// pgp_keys or a pgp_key are refused.
var ErrNotSupported = errors.New("PGP keys are not supported on this build")

// Entity stands in for openpgp.Entity on js/wasm so that callers passing a
// nil entity list keep compiling.
type Entity struct{}

// EncryptShares always fails on js/wasm; see ErrNotSupported.
func EncryptShares(_ [][]byte, _ []string) ([]string, [][]byte, error) {
	return nil, nil, ErrNotSupported
}

// GetFingerprints always fails on js/wasm; see ErrNotSupported.
func GetFingerprints(_ []string, _ []*Entity) ([]string, error) {
	return nil, ErrNotSupported
}

// GetEntities always fails on js/wasm; see ErrNotSupported.
func GetEntities(_ []string) ([]*Entity, error) {
	return nil, ErrNotSupported
}

// DecryptBytes always fails on js/wasm; see ErrNotSupported.
func DecryptBytes(_, _ string) (*bytes.Buffer, error) {
	return nil, ErrNotSupported
}
