// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"log"
)

// autoJoinDiscoverer expands a raft auto-join configuration string into the
// list of candidate cluster addresses. The production implementation is
// hashicorp/go-discover; see raft_discover_native.go and raft_discover_js.go.
type autoJoinDiscoverer interface {
	Addrs(cfg string, l *log.Logger) ([]string, error)
}
