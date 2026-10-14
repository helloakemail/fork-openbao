// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package jwtauth

import (
	"context"
	"errors"
)

// The js/wasm build excludes the Google Workspace provider: the Admin SDK
// client pulls in google.golang.org/api, cloud.google.com/go/auth, s2a-go
// and their otel instrumentation. It stays in ProviderMap so configuring it
// fails with a clear error; every other provider is unaffected.

type GSuiteProvider struct{}

func (g *GSuiteProvider) Initialize(context.Context, *jwtConfig) error {
	return errors.New("the gsuite (Google Workspace) provider is not supported on this build")
}

// SensitiveKeys matches the native provider so config reads redact the same keys.
func (g *GSuiteProvider) SensitiveKeys() []string {
	return []string{"gsuite_service_account"}
}
