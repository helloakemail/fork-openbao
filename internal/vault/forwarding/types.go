// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package forwarding

import (
	"time"
)

type NodeHAConnectionInfo struct {
	NodeInfo       *NodeInformation
	LastHeartbeat  time.Time
	Version        string
	UpgradeVersion string
}
