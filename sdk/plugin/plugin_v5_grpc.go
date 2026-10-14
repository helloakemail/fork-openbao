// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package plugin

import (
	"context"
	"errors"

	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin/pb"
)

// newExternalBackendV5 starts (or reuses) an external plugin process for the
// backend and returns a gRPC client implementation of it.
func newExternalBackendV5(ctx context.Context, pluginName string, pluginType consts.PluginType, pluginVersion string, sys pluginutil.LookRunnerUtil, conf *logical.BackendConfig) (logical.Backend, error) {
	// create a backendPluginClient instance
	config := pluginutil.PluginClientConfig{
		Name:            pluginName,
		PluginSets:      PluginSet,
		PluginType:      pluginType,
		Version:         pluginVersion,
		HandshakeConfig: HandshakeConfig,
		Logger:          conf.Logger.Named(pluginName),
		AutoMTLS:        true,
		Wrapper:         sys,
	}
	return NewPluginClientV5(ctx, sys, config)
}

// PluginSet is the map of plugins we can dispense.
var PluginSet = map[int]plugin.PluginSet{
	5: {
		"backend": &GRPCBackendPlugin{},
	},
}

func Dispense(rpcClient plugin.ClientProtocol, pluginClient pluginutil.PluginClient) (logical.Backend, error) {
	// Request the plugin
	raw, err := rpcClient.Dispense("backend")
	if err != nil {
		return nil, err
	}

	var backend logical.Backend
	// We should have a logical backend type now. This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	switch c := raw.(type) {
	case *backendGRPCPluginClient:
		// This is an abstraction leak from go-plugin but it is necessary in
		// order to enable multiplexing on multiplexed plugins
		c.client = pb.NewBackendClient(pluginClient.Conn())
		c.versionClient = logical.NewPluginVersionClient(pluginClient.Conn())

		backend = c
	default:
		return nil, errors.New("unsupported plugin client type")
	}

	return &BackendPluginClientV5{
		client:  pluginClient,
		Backend: backend,
	}, nil
}

func NewPluginClientV5(ctx context.Context, sys pluginutil.RunnerUtil, config pluginutil.PluginClientConfig) (logical.Backend, error) {
	pluginClient, err := sys.NewPluginClient(ctx, config)
	if err != nil {
		return nil, err
	}

	// Request the plugin
	raw, err := pluginClient.Dispense("backend")
	if err != nil {
		return nil, err
	}

	var backend logical.Backend
	var transport string
	// We should have a logical backend type now. This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	switch c := raw.(type) {
	case *backendGRPCPluginClient:
		// This is an abstraction leak from go-plugin but it is necessary in
		// order to enable multiplexing on multiplexed plugins
		c.client = pb.NewBackendClient(pluginClient.Conn())
		c.versionClient = logical.NewPluginVersionClient(pluginClient.Conn())

		backend = c
		transport = "gRPC"
	default:
		return nil, errors.New("unsupported plugin client type")
	}

	// Wrap the backend in a tracing middleware
	if config.Logger.IsTrace() {
		backend = &BackendTracingMiddleware{
			logger: config.Logger.With("transport", transport),
			next:   backend,
		}
	}

	return &BackendPluginClientV5{
		client:  pluginClient,
		Backend: backend,
	}, nil
}
