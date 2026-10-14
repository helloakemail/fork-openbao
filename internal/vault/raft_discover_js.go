// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package vault

import (
	"errors"
	"log"
)

// On js/wasm there is no raft storage and therefore no auto-join. Keeping
// go-discover out of the build also drops the AWS, Azure, GCE, vSphere and
// Kubernetes SDKs it pulls in, which are a large share of the binary.
func newDiscover() (autoJoinDiscoverer, error) {
	return noAutoJoin{}, nil
}

type noAutoJoin struct{}

func (noAutoJoin) Addrs(string, *log.Logger) ([]string, error) {
	return nil, errors.New("raft auto-join is not supported on js/wasm")
}
