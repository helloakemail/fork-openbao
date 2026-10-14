// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package vault

import (
	"context"

	log "github.com/hashicorp/go-hclog"
	"github.com/mitchellh/go-testing-interface"
	v5 "github.com/openbao/openbao/sdk/v2/database/dbplugin/v5"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	backendplugin "github.com/openbao/openbao/sdk/v2/plugin"
)

// TestRunTestPlugin runs the testFunc which has already been registered to the
// plugin catalog and returns a pluginClient. This can be called after calling
// TestAddTestPlugin.
func TestRunTestPlugin(t testing.T, c *Core, pluginType consts.PluginType, pluginName string) *pluginClient {
	t.Helper()
	config := TestPluginClientConfig(c, pluginType, pluginName)
	client, err := c.pluginCatalog.NewPluginClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	return client
}

func TestPluginClientConfig(c *Core, pluginType consts.PluginType, pluginName string) pluginutil.PluginClientConfig {
	dsv := TestDynamicSystemView(c, nil)
	switch pluginType {
	case consts.PluginTypeCredential, consts.PluginTypeSecrets:
		return pluginutil.PluginClientConfig{
			Name:            pluginName,
			PluginType:      pluginType,
			PluginSets:      backendplugin.PluginSet,
			HandshakeConfig: backendplugin.HandshakeConfig,
			Logger:          log.NewNullLogger(),
			AutoMTLS:        true,
			IsMetadataMode:  false,
			Wrapper:         dsv,
		}
	case consts.PluginTypeDatabase:
		return pluginutil.PluginClientConfig{
			Name:            pluginName,
			PluginType:      pluginType,
			PluginSets:      v5.PluginSets,
			HandshakeConfig: v5.HandshakeConfig,
			Logger:          log.NewNullLogger(),
			AutoMTLS:        true,
			IsMetadataMode:  false,
			Wrapper:         dsv,
		}
	}
	return pluginutil.PluginClientConfig{}
}
