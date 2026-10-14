// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package dbplugin

import (
	"context"
	"errors"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"github.com/openbao/openbao/sdk/v2/database/dbplugin/v5/proto"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var _ logical.PluginVersioner = (*DatabasePluginClient)(nil)

type DatabasePluginClient struct {
	client pluginutil.PluginClient
	Database
}

func (dc *DatabasePluginClient) PluginVersion() logical.PluginVersion {
	if versioner, ok := dc.Database.(logical.PluginVersioner); ok {
		return versioner.PluginVersion()
	}
	return logical.EmptyPluginVersion
}

// This wraps the Close call and ensures we both close the database connection
// and kill the plugin.
func (dc *DatabasePluginClient) Close() error {
	err := dc.Database.Close()
	err = errors.Join(err, dc.client.Close())

	return err
}

// pluginSets is the map of plugins we can dispense.
var PluginSets = map[int]plugin.PluginSet{
	5: {
		"database": &GRPCDatabasePlugin{},
	},
	6: {
		"database": &GRPCDatabasePlugin{},
	},
}

// NewPluginClient returns a databaseRPCClient with a connection to a running
// plugin.
func NewPluginClient(ctx context.Context, sys pluginutil.RunnerUtil, config pluginutil.PluginClientConfig) (Database, error) {
	pluginClient, err := sys.NewPluginClient(ctx, config)
	if err != nil {
		return nil, err
	}

	// Request the plugin
	raw, err := pluginClient.Dispense("database")
	if err != nil {
		return nil, err
	}

	// We should have a database type now. This feels like a normal interface
	// implementation but is in fact over an RPC connection.
	var db Database
	switch c := raw.(type) {
	case gRPCClient:
		// This is an abstraction leak from go-plugin but it is necessary in
		// order to enable multiplexing on multiplexed plugins
		c.client = proto.NewDatabaseClient(pluginClient.Conn())
		c.versionClient = logical.NewPluginVersionClient(pluginClient.Conn())

		db = c
	default:
		return nil, errors.New("unsupported client type")
	}

	return &DatabasePluginClient{
		client:   pluginClient,
		Database: db,
	}, nil
}

// newExternalDatabase creates a DatabasePluginClient instance for an external
// plugin and reports the transport it uses.
func newExternalDatabase(ctx context.Context, pluginName string, pluginVersion string, sys pluginutil.LookRunnerUtil, namedLogger log.Logger) (Database, string, error) {
	config := pluginutil.PluginClientConfig{
		Name:            pluginName,
		PluginType:      consts.PluginTypeDatabase,
		Version:         pluginVersion,
		PluginSets:      PluginSets,
		HandshakeConfig: HandshakeConfig,
		Logger:          namedLogger,
		IsMetadataMode:  false,
		AutoMTLS:        true,
		Wrapper:         sys,
	}
	// create a DatabasePluginClient instance
	db, err := NewPluginClient(ctx, sys, config)
	if err != nil {
		return nil, "", err
	}

	// Switch on the underlying database client type to get the transport
	// method.
	var transport string
	switch db.(*DatabasePluginClient).Database.(type) {
	case *gRPCClient:
		transport = "gRPC"
	}

	return db, transport, nil
}
