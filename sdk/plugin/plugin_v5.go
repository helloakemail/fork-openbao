// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var (
	ErrPluginShutdown       = errors.New("plugin is shut down")
	ErrClientInMetadataMode = errors.New("plugin client can not perform action while in metadata mode")
)

// BackendPluginClientV5 is a wrapper around backendPluginClient
// that also contains its plugin.Client instance. It's primarily
// used to cleanly kill the client on Cleanup()
type BackendPluginClientV5 struct {
	client pluginutil.PluginClient

	logical.Backend
}

type ContextKey string

func (c ContextKey) String() string {
	return "plugin" + string(c)
}

const ContextKeyPluginReload = ContextKey("plugin-reload")

// Cleanup cleans up the go-plugin client and the plugin catalog
func (b *BackendPluginClientV5) Cleanup(ctx context.Context) {
	b.Backend.Cleanup(ctx)
	if _, ok := ctx.Value(ContextKeyPluginReload).(string); ok {
		b.client.Reload() //nolint:errcheck
	} else {
		b.client.Close() //nolint:errcheck
	}
}

func (b *BackendPluginClientV5) IsExternal() bool {
	return true
}

func (b *BackendPluginClientV5) PluginVersion() logical.PluginVersion {
	if versioner, ok := b.Backend.(logical.PluginVersioner); ok {
		return versioner.PluginVersion()
	}
	return logical.EmptyPluginVersion
}

var _ logical.PluginVersioner = (*BackendPluginClientV5)(nil)

// NewBackendV5 will return an instance of an RPC-based client implementation of
// the backend for external plugins, or a concrete implementation of the
// backend if it is a builtin backend. The backend is returned as a
// logical.Backend interface.
func NewBackendV5(ctx context.Context, pluginName string, pluginType consts.PluginType, pluginVersion string, sys pluginutil.LookRunnerUtil, conf *logical.BackendConfig) (logical.Backend, error) {
	// Look for plugin in the plugin catalog
	pluginRunner, err := sys.LookupPluginVersion(ctx, pluginName, pluginType, pluginVersion)
	if err != nil {
		return nil, err
	}

	var backend logical.Backend
	if pluginRunner.Builtin {
		// Plugin is builtin so we can retrieve an instance of the interface
		// from the pluginRunner. Then cast it to logical.Factory.
		rawFactory, err := pluginRunner.BuiltinFactory()
		if err != nil {
			return nil, fmt.Errorf("error getting plugin type: %q", err)
		}

		if factory, ok := rawFactory.(logical.Factory); !ok {
			return nil, fmt.Errorf("unsupported backend type: %q", pluginName)
		} else {
			if backend, err = factory(ctx, conf); err != nil {
				return nil, err
			}
		}
	} else {
		backend, err = newExternalBackendV5(ctx, pluginName, pluginType, pluginVersion, sys, conf)
		if err != nil {
			return nil, err
		}
	}

	return backend, nil
}
