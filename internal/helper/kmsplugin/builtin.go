// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package kmsplugin

import (
	"fmt"

	kmstransit "github.com/openbao/go-kms-wrapping/kms/transit/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/v2/internal/command/server"
)

// This file holds what the catalog needs on every platform: the builtin
// KMSes, wrappers and their metadata, and plugin config parsing. Running
// external KMS plugins lives in catalog.go, kms.go, wrapper.go and
// metadata.go, which are excluded from the js/wasm build (see catalog_js.go).

var builtinKMSes = map[string]func() kms.KMS{
	"transit": kmstransit.New,
}

// builtinWrappers lives in wrapper_builtin.go (native) and
// wrapper_builtin_js.go (js/wasm: static only).

// toWrapper is a hack to go from func() <concrete wrapper type> to func()
// wrapping.Wrapper, as constructors in go-kms-wrapping tend to return the
// concrete type.
func toWrapper[T wrapping.Wrapper](f func() T) func() wrapping.Wrapper {
	return func() wrapping.Wrapper { return f() }
}

var builtinMetadata = map[string]Metadata{
	"transit": {
		SensitiveKMSFields: kmstransit.SensitiveKMSFields,
	},
}

// buildConfigLookup builds a lookup map of plugin configs by name and ensures
// there are no naming or versioning conflicts.
func buildConfigLookup(plugins []*server.PluginConfig) (map[string]*server.PluginConfig, error) {
	index := make(map[string]*server.PluginConfig)
	for _, plugin := range plugins {
		// Ignore plugins that aren't type KMS.
		if typ, _ := consts.ParsePluginType(plugin.Type); typ != consts.PluginTypeKMS {
			continue
		}
		// KMS plugins only support one version at a time.
		if _, ok := index[plugin.Name]; ok {
			return nil, fmt.Errorf("cannot register several versions of plugin %q", plugin.Name)
		}
		index[plugin.Name] = plugin
	}
	return index, nil
}
