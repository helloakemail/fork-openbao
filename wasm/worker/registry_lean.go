// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js && wasm && baolean

package main

import (
	"slices"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/logical"
	credAppRole "github.com/openbao/openbao/v2/internal/builtin/credential/approle"
	credCert "github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	credJWT "github.com/openbao/openbao/v2/internal/builtin/credential/jwt"
	credUserpass "github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	dbPostgres "github.com/openbao/openbao/v2/internal/builtin/database/postgresql"
	logicalKv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	logicalPki "github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	logicalSsh "github.com/openbao/openbao/v2/internal/builtin/logical/ssh"
	logicalTotp "github.com/openbao/openbao/v2/internal/builtin/logical/totp"
	logicalTransit "github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/vault"
)

// pluginRegistry is a reduced builtin plugin set for the Worker build. It
// leaves out everything that drags in a cloud or cluster SDK (kubernetes
// auth/secrets, rabbitmq, cassandra, influxdb, mysql, valkey) since those
// are the bulk of the binary and rarely make sense from a Worker.
var pluginRegistry vault.BuiltinRegistry = &leanRegistry{
	credential: map[string]logical.Factory{
		"approle":  credAppRole.Factory,
		"cert":     credCert.Factory,
		"jwt":      credJWT.Factory,
		"oidc":     credJWT.Factory,
		"userpass": credUserpass.Factory,
	},
	secrets: map[string]logical.Factory{
		"kv":      logicalKv.Factory,
		"pki":     logicalPki.Factory,
		"ssh":     logicalSsh.Factory,
		"totp":    logicalTotp.Factory,
		"transit": logicalTransit.Factory,
	},
	database: map[string]func() (any, error){
		"postgresql-database-plugin": dbPostgres.New,
	},
}

type leanRegistry struct {
	credential map[string]logical.Factory
	secrets    map[string]logical.Factory
	database   map[string]func() (any, error)
}

func (r *leanRegistry) Get(name string, pluginType consts.PluginType) (func() (any, error), bool) {
	switch pluginType {
	case consts.PluginTypeCredential:
		if f, ok := r.credential[name]; ok {
			return func() (any, error) { return f, nil }, true
		}
	case consts.PluginTypeSecrets:
		if f, ok := r.secrets[name]; ok {
			return func() (any, error) { return f, nil }, true
		}
	case consts.PluginTypeDatabase:
		if f, ok := r.database[name]; ok {
			return f, true
		}
	}
	return nil, false
}

func (r *leanRegistry) Keys(pluginType consts.PluginType) []string {
	var keys []string
	switch pluginType {
	case consts.PluginTypeCredential:
		for k := range r.credential {
			keys = append(keys, k)
		}
	case consts.PluginTypeSecrets:
		for k := range r.secrets {
			keys = append(keys, k)
		}
	case consts.PluginTypeDatabase:
		for k := range r.database {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func (r *leanRegistry) Contains(name string, pluginType consts.PluginType) bool {
	return slices.Contains(r.Keys(pluginType), name)
}

func (r *leanRegistry) DeprecationStatus(name string, pluginType consts.PluginType) (consts.DeprecationStatus, bool) {
	if r.Contains(name, pluginType) {
		return consts.Supported, true
	}
	return consts.Unknown, false
}
