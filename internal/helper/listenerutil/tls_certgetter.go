// Copyright (c) 2024 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package listenerutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/cli"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/reloadutil"

	"github.com/openbao/openbao/v2/internal/helper/configutil"
)

type ReloadableCertGetter interface {
	Reload() error
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

func NewCertificateGetter(l *configutil.Listener, ui cli.Ui, logger hclog.Logger) (ReloadableCertGetter, error) {
	// Assume a validated listener here. Prefer the certificate if is set
	// by path in the listener configuration, otherwise do ACME certificate
	// acquisition.
	if l.TLSCertFile != "" {
		cg := reloadutil.NewCertificateGetter(l.TLSCertFile, l.TLSKeyFile, "")
		if err := cg.Reload(); err != nil {
			// We try the key without a passphrase first and if we get an incorrect
			// passphrase response, try again after prompting for a passphrase
			if errwrap.Contains(err, x509.IncorrectPasswordError.Error()) {
				var passphrase string
				passphrase, err = ui.AskSecret(fmt.Sprintf("Enter passphrase for %s:", l.TLSKeyFile))
				if err == nil {
					cg = reloadutil.NewCertificateGetter(l.TLSCertFile, l.TLSKeyFile, passphrase)
					if err = cg.Reload(); err == nil {
						return cg, nil
					}

					return nil, fmt.Errorf("error loading TLS cert with password: %w", err)
				}
			}

			return nil, fmt.Errorf("error loading TLS cert: %w", err)
		}

		return cg, nil
	}

	return newACMECertGetter(l, logger)
}
