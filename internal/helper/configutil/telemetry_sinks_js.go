// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

package configutil

import (
	"errors"

	metrics "github.com/hashicorp/go-metrics/compat"
)

// The Prometheus, Circonus and DogStatsD sinks are excluded from the js/wasm
// build; only the in-memory sink (and statsd/statsite) remain.

func newPrometheusSink(_ *SetupTelemetryOpts) (metrics.MetricSink, error) {
	return nil, errors.New("prometheus telemetry is not supported on this build")
}

func newCirconusSink(_ *SetupTelemetryOpts) (metrics.MetricSink, error) {
	return nil, errors.New("circonus telemetry is not supported on this build")
}

func newDogStatsdSink(_ *SetupTelemetryOpts, _ string) (metrics.MetricSink, error) {
	return nil, errors.New("dogstatsd telemetry is not supported on this build")
}
