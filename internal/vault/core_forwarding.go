// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package vault

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/vault/forwarding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Starts the listeners and servers necessary to handle forwarded requests
func (c *Core) startForwarding(ctx context.Context) error {
	c.logger.Debug("request forwarding setup function")
	defer c.logger.Debug("leaving request forwarding setup function")

	// Clean up in case we have transitioned from a client to a server
	c.clearForwardingClients()

	clusterListener := c.getClusterListener()
	if c.ha == nil || clusterListener == nil {
		c.logger.Debug("request forwarding not setup")
		return nil
	}

	fwdCfg := forwarding.ForwardingConfig{
		HA:                           c.ha,
		ClusterHandler:               c.clusterHandler,
		ClusterHeartbeatInterval:     c.clusterHeartbeatInterval,
		RaftFollowerStates:           c.raftFollowerStates,
		ClusterPeerClusterAddrsCache: c.clusterPeerClusterAddrsCache,
	}

	handler, err := forwarding.NewRequestForwardingHandler(c, fwdCfg, clusterListener.Server())
	if err != nil {
		return err
	}

	clusterListener.AddHandler(consts.RequestForwardingALPN, handler)

	return nil
}

// refreshRequestForwardingConnection ensures that the client/transport are
// alive and that the current active address value matches the most
// recently-known address.
func (c *Core) refreshRequestForwardingConnection(ctx context.Context, clusterAddr string) error {
	c.logger.Debug("refreshing forwarding connection", "clusterAddr", clusterAddr)
	defer c.logger.Debug("done refreshing forwarding connection", "clusterAddr", clusterAddr)

	// Clean things up first
	c.clearForwardingClients()

	// If we don't have anything to connect to, just return
	if clusterAddr == "" {
		return nil
	}

	clusterURL, err := url.Parse(clusterAddr)
	if err != nil {
		c.logger.Error("error parsing cluster address attempting to refresh forwarding connection", "error", err)
		return err
	}

	parsedCert := c.localClusterParsedCert.Load()
	if parsedCert == nil {
		c.logger.Error("no request forwarding cluster certificate found")
		return errors.New("no request forwarding cluster certificate found")
	}

	clusterListener := c.getClusterListener()
	if clusterListener == nil {
		c.logger.Error("no cluster listener configured")
		return nil
	}

	clusterListener.AddClient(consts.RequestForwardingALPN, forwarding.NewRequestForwardingClusterClient(c))

	// Set up grpc forwarding handling
	// It's not really insecure, but we have to dial manually to get the
	// ALPN header right. It's just "insecure" because GRPC isn't managing
	// the TLS state.
	dctx, cancelFunc := context.WithCancel(ctx)
	rpcClientConn, err := grpc.NewClient(
		fmt.Sprintf("passthrough:///%s", clusterURL.Host),
		grpc.WithContextDialer(clusterListener.GetContextDialerFunc(ctx, consts.RequestForwardingALPN)),
		grpc.WithTransportCredentials(
			insecure.NewCredentials(), // it's not, we handle it in the dialer
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 2 * c.clusterHeartbeatInterval,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(math.MaxInt32),
			grpc.MaxCallSendMsgSize(math.MaxInt32),
		),
		grpc.WithUnaryInterceptor(forwarding.LegacyPackageFallback),
	)
	if err != nil {
		cancelFunc()
		c.logger.Error("err setting up forwarding rpc client", "error", err)
		return err
	}

	client := forwarding.NewClient(
		c,
		rpcClientConn,
		dctx,
		time.NewTicker(c.clusterHeartbeatInterval),
		time.NewTicker(c.clusterNamespaceSyncInterval),
	)
	client.Start()

	oldCtx := c.rpcClientConnContext.Swap(NewAtomicContext(dctx, cancelFunc))
	oldCtx.Cancel()

	c.rpcForwardingClient.Store(client)

	if _, ok := c.underlyingPhysical.(physical.CacheInvalidationBackend); !ok {
		c.logger.Info("restarting standby as active node has changed; may enable grpc invalidation")
		c.Restart()
	}

	return nil
}
