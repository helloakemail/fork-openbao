// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package metricsutil

import (
	"github.com/openbao/openbao/sdk/v2/logical"
)

// writePrometheusMetrics is unavailable on js/wasm: the Prometheus client and
// sink are excluded from this build, so PrometheusEnabled is never true there.
func writePrometheusMetrics(resp *logical.Response) *logical.Response {
	resp.Data[logical.HTTPRawBody] = "prometheus is not supported on this build"
	return resp
}
