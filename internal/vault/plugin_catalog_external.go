// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package vault

import (
	"context"
	"errors"
	"fmt"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-secure-stdlib/base62"
	v4 "github.com/openbao/openbao/sdk/v2/database/dbplugin"
	v5 "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	backendplugin "github.com/openbao/openbao/sdk/v2/plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// This file holds the parts of the plugin catalog that start, talk to and
// stop external plugin processes (hashicorp/go-plugin over gRPC). They are
// excluded from the js/wasm build, see plugin_catalog_external_js.go.

// externalPlugin holds client connections for multiplexed and
// non-multiplexed plugin processes
type externalPlugin struct {
	// connections holds client connections by ID
	connections map[string]*pluginClient

	multiplexingSupport bool
}

// pluginClient represents a connection to a plugin process
type pluginClient struct {
	logger log.Logger

	// id is the connection ID
	id  string
	pid int

	// client handles the lifecycle of a plugin process
	// multiplexed plugins share the same client
	client      *plugin.Client
	clientConn  grpc.ClientConnInterface
	cleanupFunc func() error
	reloadFunc  func() error

	plugin.ClientProtocol
}

type pluginClientConn struct {
	*grpc.ClientConn
	id string
}

var _ grpc.ClientConnInterface = &pluginClientConn{}

func (d *pluginClientConn) Invoke(ctx context.Context, method string, args any, reply any, opts ...grpc.CallOption) error {
	// Inject ID to the context
	md := metadata.Pairs(pluginutil.MultiplexingCtxKey, d.id)
	idCtx := metadata.NewOutgoingContext(ctx, md)

	return d.ClientConn.Invoke(idCtx, method, args, reply, opts...)
}

func (d *pluginClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	// Inject ID to the context
	md := metadata.Pairs(pluginutil.MultiplexingCtxKey, d.id)
	idCtx := metadata.NewOutgoingContext(ctx, md)

	return d.ClientConn.NewStream(idCtx, desc, method, opts...)
}

func (p *pluginClient) Conn() grpc.ClientConnInterface {
	return p.clientConn
}

func (p *pluginClient) Reload() error {
	p.logger.Debug("reload external plugin process")
	return p.reloadFunc()
}

// reloadExternalPlugin
// This should be called with the write lock held.
func (c *PluginCatalog) reloadExternalPlugin(key externalPluginsKey, id, path string) error {
	extPlugin, ok := c.externalPlugins[key]
	if !ok {
		return errors.New("plugin client not found")
	}
	if !extPlugin.multiplexingSupport {
		err := c.cleanupExternalPlugin(key, id, path)
		if err != nil {
			return err
		}
		return nil
	}

	pc, ok := extPlugin.connections[id]
	if !ok {
		return fmt.Errorf("%w id: %s", ErrPluginConnectionNotFound, id)
	}

	delete(c.externalPlugins, key)
	pc.client.Kill()
	c.logger.Debug("killed external plugin process for reload", "path", path, "pid", pc.pid)

	return nil
}

// Close calls the plugin client's cleanupFunc to do any necessary cleanup on
// the plugin client and the PluginCatalog. This implements the
// plugin.ClientProtocol interface.
func (p *pluginClient) Close() error {
	p.logger.Debug("cleaning up plugin client connection", "id", p.id)
	return p.cleanupFunc()
}

// cleanupExternalPlugin will kill plugin processes and perform any necessary
// cleanup on the externalPlugins map for multiplexed and non-multiplexed
// plugins. This should be called with the write lock held.
func (c *PluginCatalog) cleanupExternalPlugin(key externalPluginsKey, id, path string) error {
	extPlugin, ok := c.externalPlugins[key]
	if !ok {
		return errors.New("plugin client not found")
	}

	pc, ok := extPlugin.connections[id]
	if !ok {
		// this can happen if the backend is reloaded due to a plugin process
		// being killed out of band
		c.logger.Warn(ErrPluginConnectionNotFound.Error(), "id", id)
		return fmt.Errorf("%w id: %s", ErrPluginConnectionNotFound, id)
	}

	delete(extPlugin.connections, id)
	c.logger.Debug("removed plugin client connection", "id", id)

	if !extPlugin.multiplexingSupport {
		pc.client.Kill()

		if len(extPlugin.connections) == 0 {
			delete(c.externalPlugins, key)
		}
		c.logger.Debug("killed external plugin process", "path", path, "pid", pc.pid)
	} else if len(extPlugin.connections) == 0 || pc.client.Exited() {
		pc.client.Kill()
		delete(c.externalPlugins, key)
		c.logger.Debug("killed external multiplexed plugin process", "path", path, "pid", pc.pid)
	}

	return nil
}

func (c *PluginCatalog) getExternalPlugin(key externalPluginsKey) *externalPlugin {
	if extPlugin, ok := c.externalPlugins[key]; ok {
		return extPlugin
	}

	return c.newExternalPlugin(key)
}

func (c *PluginCatalog) newExternalPlugin(key externalPluginsKey) *externalPlugin {
	if c.externalPlugins == nil {
		c.externalPlugins = make(map[externalPluginsKey]*externalPlugin)
	}

	extPlugin := &externalPlugin{
		connections: make(map[string]*pluginClient),
	}

	c.externalPlugins[key] = extPlugin
	return extPlugin
}

// NewPluginClient returns a client for managing the lifecycle of a plugin
// process
func (c *PluginCatalog) NewPluginClient(ctx context.Context, config pluginutil.PluginClientConfig) (*pluginClient, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if config.Name == "" {
		return nil, errors.New("no name provided for plugin")
	}
	if config.PluginType == consts.PluginTypeUnknown {
		return nil, errors.New("no plugin type provided")
	}

	pluginRunner, err := c.get(ctx, config.Name, config.PluginType, config.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup plugin: %w", err)
	}
	if pluginRunner == nil {
		return nil, errors.New("no plugin found")
	}
	pc, err := c.newPluginClient(ctx, pluginRunner, config)
	return pc, err
}

// newPluginClient returns a client for managing the lifecycle of a plugin
// process. Callers should have the write lock held.
func (c *PluginCatalog) newPluginClient(ctx context.Context, pluginRunner *pluginutil.PluginRunner, config pluginutil.PluginClientConfig) (*pluginClient, error) {
	if pluginRunner == nil {
		return nil, errors.New("no plugin found")
	}

	key, err := makeExternalPluginsKey(pluginRunner)
	if err != nil {
		return nil, err
	}

	extPlugin := c.getExternalPlugin(key)
	id, err := base62.Random(10)
	if err != nil {
		return nil, err
	}

	pc := &pluginClient{
		id:     id,
		logger: c.logger.Named(pluginRunner.Name),
		cleanupFunc: func() error {
			c.lock.Lock()
			defer c.lock.Unlock()
			return c.cleanupExternalPlugin(key, id, pluginRunner.Command)
		},
		reloadFunc: func() error {
			c.lock.Lock()
			defer c.lock.Unlock()
			return c.reloadExternalPlugin(key, id, pluginRunner.Command)
		},
	}

	// Multiplexing support will always be false initially, but will be
	// adjusted once we query from the plugin whether it can multiplex or not
	if !extPlugin.multiplexingSupport || len(extPlugin.connections) == 0 {
		c.logger.Debug("spawning a new plugin process", "plugin_name", pluginRunner.Name, "id", id)
		client, err := pluginRunner.RunConfig(
			ctx,
			pluginutil.PluginSets(config.PluginSets),
			pluginutil.HandshakeConfig(config.HandshakeConfig),
			pluginutil.Logger(config.Logger),
			pluginutil.MetadataMode(config.IsMetadataMode),
			pluginutil.MLock(c.mlockPlugins),
			pluginutil.AutoMTLS(config.AutoMTLS),
			pluginutil.Runner(config.Wrapper),
		)
		if err != nil {
			return nil, err
		}

		pc.client = client
	} else {
		c.logger.Debug("returning existing plugin client for multiplexed plugin", "id", id)

		// get the first client, since they are all the same
		for k := range extPlugin.connections {
			pc.client = extPlugin.connections[k].client
			break
		}

		if pc.client == nil {
			return nil, errors.New("plugin client is nil")
		}
	}

	// Get the protocol client for this connection.
	// Subsequent calls to this will return the same client.
	rpcClient, err := pc.client.Client()
	if err != nil {
		return nil, err
	}

	// get the external plugin pid
	conf := pc.client.ReattachConfig()
	if conf != nil {
		pc.pid = conf.Pid
	}

	clientConn := rpcClient.(*plugin.GRPCClient).Conn

	muxed, err := pluginutil.MultiplexingSupported(ctx, clientConn, config.Name)
	if err != nil {
		return nil, err
	}

	pc.clientConn = &pluginClientConn{
		ClientConn: clientConn,
		id:         id,
	}

	pc.ClientProtocol = rpcClient

	extPlugin.connections[id] = pc
	extPlugin.multiplexingSupport = muxed

	return extPlugin.connections[id], nil
}

// getPluginTypeFromUnknown will attempt to run the plugin to determine the
// type. It will first attempt to run as a database plugin then a backend
// plugin.
func (c *PluginCatalog) getPluginTypeFromUnknown(ctx context.Context, plugin *pluginutil.PluginRunner) (consts.PluginType, error) {
	merr := &multierror.Error{}
	err := c.isDatabasePlugin(ctx, plugin)
	if err == nil {
		return consts.PluginTypeDatabase, nil
	}
	merr = multierror.Append(merr, err)

	pluginType, err := c.getBackendPluginType(ctx, plugin)
	if err == nil {
		return pluginType, nil
	}
	merr = multierror.Append(merr, err)

	return consts.PluginTypeUnknown, merr
}

// getBackendPluginType returns an error if the plugin is not a backend plugin.
func (c *PluginCatalog) getBackendPluginType(ctx context.Context, pluginRunner *pluginutil.PluginRunner) (consts.PluginType, error) {
	merr := &multierror.Error{}
	// Attempt to run as backend plugin
	config := pluginutil.PluginClientConfig{
		Name:            pluginRunner.Name,
		PluginSets:      backendplugin.PluginSet,
		HandshakeConfig: backendplugin.HandshakeConfig,
		Logger:          log.NewNullLogger(),
		IsMetadataMode:  false,
		AutoMTLS:        true,
		Wrapper:         c.wrapper,
	}

	c.logger.Debug("attempting to load backend plugin", "name", pluginRunner.Name)
	pc, err := c.newPluginClient(ctx, pluginRunner, config)
	if err != nil {
		c.logger.Debug("failed to spawn v5 backend plugin", "name", pluginRunner.Name)
		return consts.PluginTypeUnknown, fmt.Errorf("failed to spawn v5 backend plugin: %w", err)
	}

	// We spawned a subprocess, so make sure to clean it up.
	key, err := makeExternalPluginsKey(pluginRunner)
	if err != nil {
		return consts.PluginTypeUnknown, err
	}
	defer func() {
		// Close the client and cleanup the plugin process.
		err = c.cleanupExternalPlugin(key, pc.id, pluginRunner.Command)
		if err != nil {
			c.logger.Error("error closing plugin client", "error", err)
		}
	}()

	// Dispense the plugin so we can get its type.
	client, err := backendplugin.Dispense(pc.ClientProtocol, pc)
	if err != nil {
		c.logger.Debug("failed to dispense v5 backend plugin", "name", pluginRunner.Name)
		return consts.PluginTypeUnknown, fmt.Errorf("failed to dispense v5 backend plugin: %w", err)
	} else {
		c.logger.Debug("successfully dispensed v5 backend plugin", "name", pluginRunner.Name)
	}

	if err := client.Setup(ctx, &logical.BackendConfig{}); err != nil {
		return consts.PluginTypeUnknown, err
	}
	backendType := client.Type()

	switch backendType {
	case logical.TypeCredential:
		return consts.PluginTypeCredential, nil
	case logical.TypeLogical:
		return consts.PluginTypeSecrets, nil
	}

	if client == nil || client.Type() == logical.TypeUnknown {
		c.logger.Warn("unknown plugin type",
			"plugin name", pluginRunner.Name,
			"error", merr.Error())
	} else {
		c.logger.Warn("unsupported plugin type",
			"plugin name", pluginRunner.Name,
			"plugin type", client.Type().String(),
			"error", merr.Error())
	}

	merr = multierror.Append(merr, fmt.Errorf("failed to load plugin as backend plugin: %w", err))

	return consts.PluginTypeUnknown, merr.ErrorOrNil()
}

// getBackendRunningVersion attempts to get the plugin version
func (c *PluginCatalog) getBackendRunningVersion(ctx context.Context, pluginRunner *pluginutil.PluginRunner) (logical.PluginVersion, error) {
	// Attempt to run as backend plugin
	config := pluginutil.PluginClientConfig{
		Name:            pluginRunner.Name,
		PluginSets:      backendplugin.PluginSet,
		HandshakeConfig: backendplugin.HandshakeConfig,
		Logger:          log.NewNullLogger(),
		IsMetadataMode:  false,
		AutoMTLS:        true,
		Wrapper:         c.wrapper,
	}

	c.logger.Debug("attempting to load backend plugin", "name", pluginRunner.Name)
	pc, err := c.newPluginClient(ctx, pluginRunner, config)
	if err != nil {
		c.logger.Debug("failed to spawn v5 backend plugin", "name", pluginRunner.Name)
		return logical.EmptyPluginVersion, fmt.Errorf("failed to spawn v5 backend plugin: %w", err)
	}

	// We spawned a subprocess, so make sure to clean it up.
	key, err := makeExternalPluginsKey(pluginRunner)
	if err != nil {
		return logical.EmptyPluginVersion, err
	}
	defer func() {
		// Close the client and cleanup the plugin process.
		err = c.cleanupExternalPlugin(key, pc.id, pluginRunner.Command)
		if err != nil {
			c.logger.Error("error closing plugin client", "error", err)
		}
	}()

	// Dispense the plugin so we can get its version.
	client, err := backendplugin.Dispense(pc.ClientProtocol, pc)
	if err != nil {
		c.logger.Debug("failed to dispense v5 backend plugin", "name", pluginRunner.Name)
		return logical.EmptyPluginVersion, fmt.Errorf("failed to dispense v5 backend plugin: %w", err)
	} else {
		c.logger.Debug("successfully dispensed v5 backend plugin", "name", pluginRunner.Name)
	}

	if err := client.Setup(ctx, &logical.BackendConfig{}); err != nil {
		return logical.EmptyPluginVersion, nil
	}

	if versioner, ok := client.(logical.PluginVersioner); ok {
		return versioner.PluginVersion(), nil
	}

	return logical.EmptyPluginVersion, nil
}

// getDatabaseRunningVersion returns the version reported by a database plugin
func (c *PluginCatalog) getDatabaseRunningVersion(ctx context.Context, pluginRunner *pluginutil.PluginRunner) (logical.PluginVersion, error) {
	merr := &multierror.Error{}
	config := pluginutil.PluginClientConfig{
		Name:            pluginRunner.Name,
		PluginSets:      v5.PluginSets,
		PluginType:      consts.PluginTypeDatabase,
		Version:         pluginRunner.Version,
		HandshakeConfig: v5.HandshakeConfig,
		Logger:          log.Default(),
		IsMetadataMode:  true,
		AutoMTLS:        true,
		Wrapper:         c.wrapper,
	}

	// Attempt to run as database V5+ multiplexed plugin
	c.logger.Debug("attempting to load database plugin as v5", "name", pluginRunner.Name)
	v5Client, err := c.newPluginClient(ctx, pluginRunner, config)
	if err == nil {
		key, err := makeExternalPluginsKey(pluginRunner)
		if err != nil {
			return logical.EmptyPluginVersion, err
		}
		defer func() {
			// Close the client and cleanup the plugin process
			err = c.cleanupExternalPlugin(key, v5Client.id, pluginRunner.Command)
			if err != nil {
				c.logger.Error("error closing plugin client", "error", err)
			}
		}()

		raw, err := v5Client.Dispense("database")
		if err != nil {
			return logical.EmptyPluginVersion, err
		}
		if versioner, ok := raw.(logical.PluginVersioner); ok {
			return versioner.PluginVersion(), nil
		}
		return logical.EmptyPluginVersion, nil
	}
	merr = multierror.Append(merr, fmt.Errorf("failed to load plugin as database v5: %w", err))

	c.logger.Debug("attempting to load database plugin as v4", "name", pluginRunner.Name)
	v4Client, err := v4.NewPluginClient(ctx, c.wrapper, pluginRunner, log.NewNullLogger(), true)
	if err == nil {
		// Close the client and cleanup the plugin process
		defer func() {
			err = v4Client.Close()
			if err != nil {
				c.logger.Error("error closing plugin client", "error", err)
			}
		}()

		if versioner, ok := v4Client.(logical.PluginVersioner); ok {
			return versioner.PluginVersion(), nil
		}

		return logical.EmptyPluginVersion, nil
	}
	merr = multierror.Append(merr, fmt.Errorf("failed to load plugin as database v4: %w", err))
	return logical.EmptyPluginVersion, merr
}

// isDatabasePlugin returns an error if the plugin is not a database plugin.
func (c *PluginCatalog) isDatabasePlugin(ctx context.Context, pluginRunner *pluginutil.PluginRunner) error {
	merr := &multierror.Error{}
	config := pluginutil.PluginClientConfig{
		Name:            pluginRunner.Name,
		PluginSets:      v5.PluginSets,
		PluginType:      consts.PluginTypeDatabase,
		Version:         pluginRunner.Version,
		HandshakeConfig: v5.HandshakeConfig,
		Logger:          log.NewNullLogger(),
		IsMetadataMode:  true,
		AutoMTLS:        true,
		Wrapper:         c.wrapper,
	}

	// Attempt to run as database V5+ multiplexed plugin
	c.logger.Debug("attempting to load database plugin as v5", "name", pluginRunner.Name)
	v5Client, err := c.newPluginClient(ctx, pluginRunner, config)
	if err == nil {
		// Close the client and cleanup the plugin process
		key, err := makeExternalPluginsKey(pluginRunner)
		if err != nil {
			return err
		}
		err = c.cleanupExternalPlugin(key, v5Client.id, pluginRunner.Command)
		if err != nil {
			c.logger.Error("error closing plugin client", "error", err)
		}

		return nil
	}
	merr = multierror.Append(merr, fmt.Errorf("failed to load plugin as database v5: %w", err))

	c.logger.Debug("attempting to load database plugin as v4", "name", pluginRunner.Name)
	v4Client, err := v4.NewPluginClient(ctx, c.wrapper, pluginRunner, log.NewNullLogger(), true)
	if err == nil {
		// Close the client and cleanup the plugin process
		err = v4Client.Close()
		if err != nil {
			c.logger.Error("error closing plugin client", "error", err)
		}

		return nil
	}
	merr = multierror.Append(merr, fmt.Errorf("failed to load plugin as database v4: %w", err))

	return merr.ErrorOrNil()
}
