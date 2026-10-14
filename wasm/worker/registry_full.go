// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js && wasm && !baolean

package main

import (
	"github.com/openbao/openbao/v2/internal/helper/builtinplugins"
	"github.com/openbao/openbao/v2/internal/vault"
)

// pluginRegistry is the complete OpenBao builtin plugin set. Build with
// -tags baolean to swap in the much smaller registry_lean.go set instead.
var pluginRegistry vault.BuiltinRegistry = builtinplugins.Registry
