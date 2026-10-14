// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package kmsplugin

import (
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/kmip/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/static/v2"
	"github.com/openbao/go-kms-wrapping/wrappers/transit/v2"
)

var builtinWrappers = map[wrapping.WrapperType]func() wrapping.Wrapper{
	kmip.Type:    toWrapper(kmip.NewWrapper),
	static.Type:  toWrapper(static.NewWrapper),
	transit.Type: toWrapper(transit.NewWrapper),
}
