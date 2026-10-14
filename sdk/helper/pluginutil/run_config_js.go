// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package pluginutil

import (
	"errors"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
)

// ErrExternalPluginsUnsupported is returned on js/wasm wherever a code path
// would need to start an external plugin process. External plugins are
// subprocesses spoken to over gRPC (hashicorp/go-plugin); a WebAssembly
// sandbox can run neither, so this build only has builtin plugins, which run
// in-process and never reach this code.
var ErrExternalPluginsUnsupported = errors.New("external plugins are not supported on this build")

// PluginClientConfig mirrors the native type without the go-plugin specific
// fields (PluginSets, HandshakeConfig), so that logical.SystemView keeps its
// method set on js/wasm.
type PluginClientConfig struct {
	Name           string
	PluginType     consts.PluginType
	Version        string
	Logger         log.Logger
	IsMetadataMode bool
	AutoMTLS       bool
	MLock          bool
	Wrapper        RunnerUtil
}

// PluginClient mirrors the native interface without Conn(), which returns a
// gRPC connection. The remaining methods are those of go-plugin's
// ClientProtocol plus Reload. No value of this type is ever created on
// js/wasm: NewPluginClient implementations return
// ErrExternalPluginsUnsupported.
type PluginClient interface {
	Reload() error
	Close() error
	Dispense(string) (any, error)
	Ping() error
}
