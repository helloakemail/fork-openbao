// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package dbplugin

import (
	"context"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
)

// newExternalDatabase would start an external database plugin process and
// talk to it over gRPC. Neither is available on js/wasm; builtin database
// plugins are created in-process by PluginFactoryVersion and never get here.
func newExternalDatabase(_ context.Context, _ pluginutil.RunnerUtil, _ *pluginutil.PluginRunner, _ log.Logger) (Database, string, error) {
	return nil, "", pluginutil.ErrExternalPluginsUnsupported
}
