// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package kmsplugin

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
)

// builtinWrappers on js/wasm only carries the static wrapper: the KMIP client
// (ovh/kmip-go) and the transit wrapper need outbound connections a Worker
// seal cannot rely on, so they are excluded from this build. Shamir is not a
// go-kms-wrapping wrapper and is unaffected.
var builtinWrappers = map[wrapping.WrapperType]func() wrapping.Wrapper{
	static.Type: toWrapper(static.NewWrapper),
}
