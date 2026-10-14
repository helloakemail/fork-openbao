// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package oci

import (
	"context"
	"errors"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/v2/internal/command/server"
)

// errOCINotSupported is returned on js/wasm: downloading plugin images from an
// OCI registry (go-containerregistry) is excluded from this build, and there
// is no plugin directory to extract them into anyway.
var errOCINotSupported = errors.New("OCI plugin download is not supported on this build")

// PluginDownloader is a stub on js/wasm; see errOCINotSupported.
type PluginDownloader struct {
	config *server.Config
}

// NewPluginDownloader creates a stub downloader on js/wasm.
func NewPluginDownloader(_ string, config *server.Config, _ hclog.Logger) *PluginDownloader {
	return &PluginDownloader{config: config}
}

// Reconcile succeeds when no OCI plugins are configured and fails otherwise.
func (d *PluginDownloader) Reconcile(_ context.Context) error {
	if d.config == nil || len(d.config.Plugins) == 0 {
		return nil
	}
	return errOCINotSupported
}

// IsCached always reports false on js/wasm.
func (d *PluginDownloader) IsCached(_ *server.PluginConfig) bool { return false }

// Download always fails on js/wasm.
func (d *PluginDownloader) Download(_ context.Context, _ *server.PluginConfig, _ hclog.Logger) error {
	return errOCINotSupported
}

// Prune always fails on js/wasm.
func (d *PluginDownloader) Prune() error { return errOCINotSupported }
