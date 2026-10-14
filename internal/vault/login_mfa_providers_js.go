// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package vault

import (
	"context"
	"errors"

	"github.com/openbao/openbao/v2/internal/helper/identity/mfa"
)

// The Okta, Duo and PingID login MFA providers are excluded from the js/wasm
// build (their SDKs are large and they rely on long-polling outbound calls).
// Methods of these types can still be configured, but validating them fails.
// TOTP login MFA is unaffected.

func (c *Core) validateDuo(_ context.Context, _ *MFAFactor, _ *mfa.Config, _, _ string) error {
	return errors.New("Duo login MFA is not supported on this build")
}

func (c *Core) validateOkta(_ context.Context, _ *mfa.Config, _ string) error {
	return errors.New("Okta login MFA is not supported on this build")
}

func (c *Core) validatePingID(_ context.Context, _ *mfa.Config, _ string) error {
	return errors.New("PingID login MFA is not supported on this build")
}
