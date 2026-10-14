// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package configutil

import (
	"fmt"

	metrics "github.com/hashicorp/go-metrics/compat"
	"github.com/hashicorp/go-metrics/compat/circonus"
	"github.com/hashicorp/go-metrics/compat/datadog"
	"github.com/hashicorp/go-metrics/compat/prometheus"
)

// newPrometheusSink builds the Prometheus sink.
func newPrometheusSink(opts *SetupTelemetryOpts) (metrics.MetricSink, error) {
	prometheusOpts := prometheus.PrometheusOpts{
		Expiration: opts.Config.PrometheusRetentionTime,
	}

	return prometheus.NewPrometheusSinkFrom(prometheusOpts)
}

// newCirconusSink builds and starts the Circonus sink.
func newCirconusSink(opts *SetupTelemetryOpts) (metrics.MetricSink, error) {
	cfg := &circonus.Config{}
	cfg.Interval = opts.Config.CirconusSubmissionInterval
	cfg.CheckManager.API.TokenKey = opts.Config.CirconusAPIToken
	cfg.CheckManager.API.TokenApp = opts.Config.CirconusAPIApp
	cfg.CheckManager.API.URL = opts.Config.CirconusAPIURL
	cfg.CheckManager.Check.SubmissionURL = opts.Config.CirconusCheckSubmissionURL
	cfg.CheckManager.Check.ID = opts.Config.CirconusCheckID
	cfg.CheckManager.Check.ForceMetricActivation = opts.Config.CirconusCheckForceMetricActivation
	cfg.CheckManager.Check.InstanceID = opts.Config.CirconusCheckInstanceID
	cfg.CheckManager.Check.SearchTag = opts.Config.CirconusCheckSearchTag
	cfg.CheckManager.Check.DisplayName = opts.Config.CirconusCheckDisplayName
	cfg.CheckManager.Check.Tags = opts.Config.CirconusCheckTags
	cfg.CheckManager.Broker.ID = opts.Config.CirconusBrokerID
	cfg.CheckManager.Broker.SelectTag = opts.Config.CirconusBrokerSelectTag

	if cfg.CheckManager.API.TokenApp == "" {
		cfg.CheckManager.API.TokenApp = opts.ServiceName
	}

	if cfg.CheckManager.Check.DisplayName == "" {
		cfg.CheckManager.Check.DisplayName = opts.DisplayName
	}

	if cfg.CheckManager.Check.SearchTag == "" {
		cfg.CheckManager.Check.SearchTag = fmt.Sprintf("service:%s", opts.ServiceName)
	}

	sink, err := circonus.NewCirconusSink(cfg)
	if err != nil {
		return nil, err
	}
	sink.Start()
	return sink, nil
}

// newDogStatsdSink builds the DogStatsD (Datadog) sink.
func newDogStatsdSink(opts *SetupTelemetryOpts, hostName string) (metrics.MetricSink, error) {
	var tags []string

	if opts.Config.DogStatsDTags != nil {
		tags = opts.Config.DogStatsDTags
	}

	sink, err := datadog.NewDogStatsdSink(opts.Config.DogStatsDAddr, hostName)
	if err != nil {
		return nil, err
	}
	sink.SetTags(tags)
	return sink, nil
}
