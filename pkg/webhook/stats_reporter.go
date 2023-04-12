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

// StatsReporter reports webhook stats.
type StatsReporter interface {
	ReportRequest(ctx context.Context, namespace string, duration time.Duration)
}

type reporter struct {
	histogram instrument.Float64Histogram
}

var (
	// if service.name is not specified, the default is "unknown_service:<exe name>"
	// xref: https://opentelemetry.io/docs/reference/specification/resource/semantic_conventions/#service
	labels = []attribute.KeyValue{attribute.String("service.name", "webhook")}
)

func newStatsReporter() (StatsReporter, error) {
	var err error
	r := &reporter{}
	meter := global.Meter("webhook")

	r.histogram, err = meter.Float64Histogram(
		requestDurationMetricName,
		instrument.WithDescription("Distribution of how long it took for the azure-workload-identity mutation request"))

	if err != nil {
		return nil, err
	}
	return r, nil
}

// ReportRequest reports the request duration for the given namespace.
func (r *reporter) ReportRequest(ctx context.Context, namespace string, duration time.Duration) {
	l := append(labels, attribute.String(namespaceKey, namespace))
	r.histogram.Record(ctx, duration.Seconds(), l...)
}
