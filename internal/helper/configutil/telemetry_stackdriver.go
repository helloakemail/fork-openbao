// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package configutil

import (
	"context"
	"fmt"

	monitoring "cloud.google.com/go/monitoring/apiv3"
	stackdriver "github.com/google/go-metrics-stackdriver"
	stackdrivervault "github.com/google/go-metrics-stackdriver/vault"
	metrics "github.com/hashicorp/go-metrics/compat"
	"google.golang.org/api/option"
)

// newStackdriverSink builds the Google Cloud Monitoring (Stackdriver) sink.
func newStackdriverSink(opts *SetupTelemetryOpts) (metrics.MetricSink, error) {
	client, err := monitoring.NewMetricClient(context.Background(), option.WithUserAgent(opts.UserAgent))
	if err != nil {
		return nil, fmt.Errorf("failed to create stackdriver client: %v", err)
	}
	return stackdriver.NewSink(client, &stackdriver.Config{
		LabelExtractor: stackdrivervault.Extractor,
		Bucketer:       stackdrivervault.Bucketer,
		ProjectID:      opts.Config.StackdriverProjectID,
		Location:       opts.Config.StackdriverLocation,
		Namespace:      opts.Config.StackdriverNamespace,
		DebugLogs:      opts.Config.StackdriverDebugLogs,
	}), nil
}
