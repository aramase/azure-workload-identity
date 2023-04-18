package webhook

import (
	"context"
	"strings"
	"testing"
	"time"

	crprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/aggregation"
)

func TestReportRequest(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		duration  time.Duration
		want      string
	}{
		{
			name:      "test",
			namespace: "test",
			duration:  1 * time.Second,
			want: `
			# HELP apiserver_envelope_encryption_kms_operations_latency_seconds [ALPHA] KMS operation duration with gRPC error code status total.
			`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			registry := crprometheus.NewRegistry()
			exporter, err := prometheus.New(prometheus.WithRegisterer(registry))
			if err != nil {
				t.Fatal(err)
			}

			meterProvider := metric.NewMeterProvider(
				metric.WithReader(exporter),
				metric.WithView(metric.NewView(
					metric.Instrument{Name: "azwi_*"},
					metric.Stream{
						Aggregation: aggregation.ExplicitBucketHistogram{
							Boundaries: []float64{0.001, 0.002, 0.003, 0.004, 0.005, 0.006, 0.007, 0.008, 0.009, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1, 1.5, 2, 2.5, 3},
						}},
				)),
			)

			global.SetMeterProvider(meterProvider)
			r, err := newStatsReporter()
			if err != nil {
				t.Fatal(err)
			}
			r.ReportRequest(ctx, test.namespace, test.duration)
			if err = testutil.GatherAndCompare(registry, strings.NewReader(test.want), "azwi_mutation_reque_bucket"); err != nil {
				t.Fatal(err)
			}
		})
	}
}
