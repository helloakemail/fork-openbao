// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package metricsutil

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// writePrometheusMetrics gathers the default Prometheus registry and writes
// it into resp in the text exposition format.
func writePrometheusMetrics(resp *logical.Response) *logical.Response {
	metricsFamilies, err := prometheus.DefaultGatherer.Gather()
	if err != nil && len(metricsFamilies) == 0 {
		resp.Data[logical.HTTPRawBody] = fmt.Sprintf("no prometheus metrics could be decoded: %s", err)
		return resp
	}

	// Initialize a byte buffer.
	buf := &bytes.Buffer{}
	defer buf.Reset()

	e := expfmt.NewEncoder(buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range metricsFamilies {
		err := e.Encode(mf)
		if err != nil {
			resp.Data[logical.HTTPRawBody] = fmt.Sprintf("error during the encoding of metrics: %s", err)
			return resp
		}
	}
	resp.Data[logical.HTTPContentType] = string(expfmt.NewFormat(expfmt.TypeTextPlain))
	resp.Data[logical.HTTPRawBody] = buf.Bytes()
	resp.Data[logical.HTTPStatusCode] = http.StatusOK
	return resp
}
