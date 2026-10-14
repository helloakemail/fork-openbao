// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package plugin

import (
	"math"

	"google.golang.org/grpc"
)

var largeMsgGRPCCallOpts []grpc.CallOption = []grpc.CallOption{
	grpc.MaxCallSendMsgSize(math.MaxInt32),
	grpc.MaxCallRecvMsgSize(math.MaxInt32),
}
