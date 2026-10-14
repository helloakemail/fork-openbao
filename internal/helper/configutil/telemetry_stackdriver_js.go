// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package configutil

import (
	"errors"

	metrics "github.com/hashicorp/go-metrics/compat"
)

// newStackdriverSink is unavailable on js/wasm: the Google Cloud Monitoring
// client (and its gRPC stack) does not build for that target.
func newStackdriverSink(opts *SetupTelemetryOpts) (metrics.MetricSink, error) {
	return nil, errors.New("stackdriver telemetry is not supported on js/wasm")
}
