// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package vault

import (
	"maps"

	"github.com/hashicorp/go-discover"
	discoverk8s "github.com/hashicorp/go-discover/provider/k8s"
)

func newDiscover() (autoJoinDiscoverer, error) {
	providers := make(map[string]discover.Provider)
	maps.Copy(providers, discover.Providers)

	providers["k8s"] = &discoverk8s.Provider{}

	return discover.New(
		discover.WithProviders(providers),
	)
}
