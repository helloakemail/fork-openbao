// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package pluginutil

import (
	"context"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/wrapping"
)

// Looker defines the plugin Lookup function that looks into the plugin catalog
// for available plugins and returns a PluginRunner
type Looker interface {
	LookupPlugin(ctx context.Context, pluginName string, pluginType consts.PluginType) (*PluginRunner, error)
	LookupPluginVersion(ctx context.Context, pluginName string, pluginType consts.PluginType, version string) (*PluginRunner, error)
}

// RunnerUtil interface defines the functions needed by the runner to wrap the
// metadata needed to run a plugin process. This includes looking up Mlock
// configuration and wrapping data in a response wrapped token.
// logical.SystemView implementations satisfy this interface.
type RunnerUtil interface {
	NewPluginClient(ctx context.Context, config PluginClientConfig) (PluginClient, error)
	ResponseWrapData(ctx context.Context, data map[string]any, ttl time.Duration, jwt bool) (*wrapping.ResponseWrapInfo, error)
	MlockEnabled() bool
	VaultVersion(ctx context.Context) (string, error)
}

// LookRunnerUtil defines the functions for both Looker and Wrapper
type LookRunnerUtil interface {
	Looker
	RunnerUtil
}

const MultiplexingCtxKey string = "multiplex_id"

// PluginRunner defines the metadata needed to run a plugin securely with
// go-plugin.
type PluginRunner struct {
	Name           string              `json:"name" structs:"name"`
	Type           consts.PluginType   `json:"type" structs:"type"`
	Version        string              `json:"version" structs:"version"`
	Command        string              `json:"command" structs:"command"`
	Args           []string            `json:"args" structs:"args"`
	Env            []string            `json:"env" structs:"env"`
	Sha256         []byte              `json:"sha256" structs:"sha256"`
	Builtin        bool                `json:"builtin" structs:"builtin"`
	BuiltinFactory func() (any, error) `json:"-" structs:"-"`
	Oci            bool                `json:"oci" structs:"oci"`
	Declarative    bool                `json:"declarative" structs:"declarative"`
}

// VersionedPlugin holds any versioning information stored about a plugin in the
// plugin catalog.
type VersionedPlugin struct {
	Type              string `json:"type"` // string instead of consts.PluginType so that we get the string form in API responses.
	Name              string `json:"name"`
	Version           string `json:"version"`
	SHA256            string `json:"sha256,omitempty"`
	Builtin           bool   `json:"builtin"`
	DeprecationStatus string `json:"deprecation_status,omitempty"`
	Oci               bool   `json:"oci" structs:"oci"`
	Declarative       bool   `json:"declarative" structs:"declarative"`

	// Pre-parsed semver struct of the Version field
	SemanticVersion *version.Version `json:"-"`
}

// CtxCancelIfCanceled takes a context cancel func and a context. If the context is
// shutdown the cancelfunc is called. This is useful for merging two cancel
// functions.
func CtxCancelIfCanceled(f context.CancelFunc, ctxCanceler context.Context) chan struct{} {
	quitCh := make(chan struct{})
	go func() {
		select {
		case <-quitCh:
		case <-ctxCanceler.Done():
			f()
		}
	}()
	return quitCh
}
