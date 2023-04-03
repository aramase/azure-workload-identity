package webhook

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/metric/instrument"
)

const (
	requestDurationMetricName = "azwi_mutation_request"

	namespaceKey = "namespace"
)

var (
	histogram instrument.Float64Histogram
	// if service.name is not specified, the default is "unknown_service:<exe name>"
	// xref: https://opentelemetry.io/docs/reference/specification/resource/semantic_conventions/#service
	labels = []attribute.KeyValue{attribute.String("service.name", "webhook")}
)

// reporter implements StatsReporter.
type reporter struct{}

// StatsReporter reports webhook metrics.
type StatsReporter interface {
	ReportRequest(ctx context.Context, namespace string, duration time.Duration)
}

func newStatsReporter() (StatsReporter, error) {
	var err error
	meter := global.Meter("azure-workload-identity")
	histogram, err = meter.Float64Histogram(requestDurationMetricName,
		instrument.WithDescription("Distribution of how long it took for the azure-workload-identity mutation request"))
	if err != nil {
		return nil, err
	}
	return &reporter{}, nil
}

// ReportRequest reports the request duration for the given namespace.
func (r *reporter) ReportRequest(ctx context.Context, namespace string, duration time.Duration) {
	l := append(labels, attribute.String(namespaceKey, namespace))
	histogram.Record(ctx, duration.Seconds(), l...)
}
