// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import "net/http"

// HandlerHandler builds the HTTP handler for a core. It is implemented by
// internal/http and used both by the server and by test clusters.
type HandlerHandler interface {
	Handler(*HandlerProperties) http.Handler
}
