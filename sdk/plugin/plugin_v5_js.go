// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package plugin

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// newExternalBackendV5 would start an external plugin process and talk to it
// over gRPC. Neither is available on js/wasm; builtin backends are created
// in-process by NewBackendV5 and never get here.
func newExternalBackendV5(_ context.Context, _ string, _ consts.PluginType, _ string, _ pluginutil.LookRunnerUtil, _ *logical.BackendConfig) (logical.Backend, error) {
	return nil, pluginutil.ErrExternalPluginsUnsupported
}
