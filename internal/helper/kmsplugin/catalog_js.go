// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package kmsplugin

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-hclog"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"github.com/openbao/openbao/v2/internal/command/server"
)

// External KMS plugins are subprocesses spoken to over gRPC
// (go-kms-wrapping/plugin and hashicorp/go-plugin). A WebAssembly sandbox can
// run neither, so on js/wasm the catalog only dispatches to the builtin KMSes
// and wrappers, and fails for names that are configured as external plugins.

var errExternalKMSUnsupported = errors.New("external KMS plugins are not supported on this build")

// Metadata mirrors go-kms-wrapping/plugin.Metadata, which is an alias of
// this type on native builds.
type Metadata struct {
	// SensitiveKMSFields are [kms.ConfigMap] fields taken by [kms.KMS.Open]
	// that are sensitive and should be censored when the config is presented
	// for display.
	SensitiveKMSFields []string

	// SensitiveKeyFields are [kms.ConfigMap] fields taken by [kms.KMS.GetKey]
	// that are sensitive and should be censored when the config is presented
	// for display.
	SensitiveKeyFields []string
}

// Catalog dispatches to builtin KMSes and wrappers.
type Catalog struct {
	logger hclog.Logger

	mu      sync.Mutex
	plugins map[string]*server.PluginConfig
}

// NewCatalog returns a new KMS plugin catalog.
func NewCatalog(logger hclog.Logger, config *server.Config) (*Catalog, error) {
	plugins, err := buildConfigLookup(config.Plugins)
	if err != nil {
		return nil, err
	}

	return &Catalog{
		logger:  logger.Named("kms"),
		plugins: plugins,
	}, nil
}

// ReloadConfig supplies the catalog with an updated server config.
func (c *Catalog) ReloadConfig(config *server.Config) error {
	plugins, err := buildConfigLookup(config.Plugins)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.plugins = plugins
	return nil
}

// checkExternal fails if name is configured as an external KMS plugin, which
// would shadow a builtin of the same name on native builds.
func (c *Catalog) checkExternal(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.plugins[name]; ok {
		return fmt.Errorf("plugin %q: %w", name, errExternalKMSUnsupported)
	}
	return nil
}

// OpenKMS creates a new builtin KMS instance and calls Open with the provided
// options.
func (c *Catalog) OpenKMS(ctx context.Context, name string, opts *kms.OpenOptions) (kms.KMS, error) {
	if err := c.checkExternal(name); err != nil {
		return nil, err
	}

	builtin, ok := builtinKMSes[name]
	if !ok {
		return nil, fmt.Errorf("unknown plugin: %s", name)
	}

	s := builtin()
	if err := s.Open(ctx, opts); err != nil {
		return nil, err
	}

	return s, nil
}

// ConfigureWrapper creates a new builtin wrapper instance and calls SetConfig
// with the provided options.
func (c *Catalog) ConfigureWrapper(ctx context.Context, name string, opts ...wrapping.Option) (wrapping.Wrapper, *wrapping.WrapperConfig, error) {
	if err := c.checkExternal(name); err != nil {
		return nil, nil, err
	}

	builtin, ok := builtinWrappers[wrapping.WrapperType(name)]
	if !ok {
		return nil, nil, fmt.Errorf("unknown wrapper: %s", name)
	}

	w := builtin()
	config, err := w.SetConfig(ctx, opts...)
	if err != nil {
		return nil, nil, err
	}

	// Enrich metadata by marking builtin vs externally provided wrappers.
	if config.Metadata == nil {
		config.Metadata = make(map[string]string, 1)
	}
	config.Metadata["builtin"] = "true"

	return w, config, nil
}

// GetMetadata returns a builtin KMS's metadata.
func (c *Catalog) GetMetadata(_ context.Context, name string) (Metadata, error) {
	if err := c.checkExternal(name); err != nil {
		return Metadata{}, err
	}

	meta, ok := builtinMetadata[name]
	if !ok {
		return Metadata{}, fmt.Errorf("unknown plugin: %s", name)
	}
	return meta, nil
}
