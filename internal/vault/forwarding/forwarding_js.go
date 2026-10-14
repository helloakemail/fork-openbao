// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package forwarding

import (
	"context"
	"errors"

	"github.com/openbao/openbao/v2/internal/helper/forwarding"
)

// HA request forwarding and invalidation streaming run over gRPC between
// cluster nodes. The js/wasm build has no gRPC and no cluster listener, so
// this package only keeps the message types and the client surface that
// internal/vault refers to. No Client is ever created on js/wasm: with no
// forwarding client, standbys answer with ErrCannotForward as they do on
// native builds before a connection to the active node exists.

var errForwardingUnsupported = errors.New("request forwarding is not supported on this build")

// InvalidationStream is the server side of the CheckInvalidations stream.
type InvalidationStream interface {
	Send(*CheckInvalidationResponse) error
}

// Client is the forwarding client of a standby node.
type Client struct{}

// ForwardRequest forwards a request to the active node.
func (c *Client) ForwardRequest(_ context.Context, _ *forwarding.Request) (*forwarding.Response, error) {
	return nil, errForwardingUnsupported
}

// CheckReplicationIndex returns the active node's storage index.
func (c *Client) CheckReplicationIndex(_ context.Context) (string, error) {
	return "", errForwardingUnsupported
}

// StreamInvalidations starts receiving invalidations from the active node.
func (c *Client) StreamInvalidations(_ context.Context) error {
	return errForwardingUnsupported
}

// Stop stops the client.
func (c *Client) Stop() error {
	return nil
}
