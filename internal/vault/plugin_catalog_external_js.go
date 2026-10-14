// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package vault

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// External plugins are subprocesses driven over gRPC (hashicorp/go-plugin).
// A WebAssembly sandbox can start neither, so on js/wasm the plugin catalog
// only serves builtin plugins, which run in-process. The functions below
// replace those of plugin_catalog_external.go and fail every attempt to run
// an external plugin.

// externalPlugin is never instantiated on js/wasm; it exists so that
// PluginCatalog keeps the same fields on every platform.
type externalPlugin struct{}

// NewPluginClient would start an external plugin process.
func (c *PluginCatalog) NewPluginClient(_ context.Context, _ pluginutil.PluginClientConfig) (pluginutil.PluginClient, error) {
	return nil, pluginutil.ErrExternalPluginsUnsupported
}

// getPluginTypeFromUnknown would run the plugin to find out its type.
func (c *PluginCatalog) getPluginTypeFromUnknown(_ context.Context, _ *pluginutil.PluginRunner) (consts.PluginType, error) {
	return consts.PluginTypeUnknown, pluginutil.ErrExternalPluginsUnsupported
}

// getBackendRunningVersion would run the plugin to ask for its version.
func (c *PluginCatalog) getBackendRunningVersion(_ context.Context, _ *pluginutil.PluginRunner) (logical.PluginVersion, error) {
	return logical.EmptyPluginVersion, pluginutil.ErrExternalPluginsUnsupported
}

// getDatabaseRunningVersion would run the plugin to ask for its version.
func (c *PluginCatalog) getDatabaseRunningVersion(_ context.Context, _ *pluginutil.PluginRunner) (logical.PluginVersion, error) {
	return logical.EmptyPluginVersion, pluginutil.ErrExternalPluginsUnsupported
}
