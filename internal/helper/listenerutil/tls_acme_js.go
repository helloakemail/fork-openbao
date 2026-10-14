// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package listenerutil

import (
	"crypto/tls"
	"errors"
	"net/http"

	"github.com/hashicorp/go-hclog"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
)

// ACMECertGetter is a placeholder on js/wasm: ACME auto-TLS (certmagic)
// needs listening sockets and a writable cache directory, neither of which
// exists in this build, so it is excluded.
type ACMECertGetter struct {
	Listener *configutil.Listener
}

var errACMENotSupported = errors.New("ACME auto-TLS (tls_acme_*) is not supported on this build")

func newACMECertGetter(_ *configutil.Listener, _ hclog.Logger) (ReloadableCertGetter, error) {
	return nil, errACMENotSupported
}

func (c *ACMECertGetter) Close() error { return nil }

func (c *ACMECertGetter) ALPNProtos() []string { return nil }

func (c *ACMECertGetter) HandleHTTPChallenge(_ http.ResponseWriter, _ *http.Request) bool {
	return false
}

func (c *ACMECertGetter) Reload() error { return nil }

func (c *ACMECertGetter) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, errACMENotSupported
}
