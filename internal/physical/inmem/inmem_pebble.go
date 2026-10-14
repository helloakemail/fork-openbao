// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package inmem

import (
	log "github.com/hashicorp/go-hclog"

	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/physical/pebbledb"
)

// newUnderlyingBackend returns the pebble-backed in-memory store used on
// native targets.
func newUnderlyingBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	return pebbledb.NewBackend(conf, logger)
}
