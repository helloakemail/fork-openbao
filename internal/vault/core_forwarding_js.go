// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package vault

import (
	"context"
)

// HA request forwarding runs over gRPC on the cluster listener, neither of
// which exist in the js/wasm build. These replace the functions in
// core_forwarding.go: the active node serves no forwarding handler and a
// standby never gets a forwarding client, so ForwardRequest returns
// ErrCannotForward and the HTTP layer falls back to redirecting the client
// to the active node, as it does natively while no connection exists.

func (c *Core) startForwarding(_ context.Context) error {
	// Clean up in case we have transitioned from a client to a server
	c.clearForwardingClients()

	if c.ha == nil || c.getClusterListener() == nil {
		c.logger.Debug("request forwarding not setup")
		return nil
	}

	c.logger.Warn("request forwarding is not supported on this build; standby nodes will redirect clients instead")
	return nil
}

func (c *Core) refreshRequestForwardingConnection(_ context.Context, clusterAddr string) error {
	// Clean things up first
	c.clearForwardingClients()

	if clusterAddr != "" {
		c.logger.Warn("request forwarding is not supported on this build; not connecting to the active node", "clusterAddr", clusterAddr)
	}
	return nil
}
