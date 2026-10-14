// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package inmem

import (
	"errors"

	log "github.com/hashicorp/go-hclog"

	"github.com/openbao/openbao/sdk/v2/physical"
)

// newUnderlyingBackend is unavailable on js/wasm: the pebble-backed in-memory
// store does not compile for that target. The WASM build uses PostgreSQL as
// its only physical backend.
func newUnderlyingBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	return nil, errors.New("inmem storage is not available on js/wasm")
}
