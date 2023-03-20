package prometheus

import (
	crprometheus "github.com/prometheus/client_golang/prometheus"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric/global"
	"go.opentelemetry.io/otel/sdk/metric"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

const (
	// ExporterName is the name of the exporter
	ExporterName = "prometheus"
)

func InitExporter() error {
	exporter, err := prometheus.New(
		prometheus.WithRegisterer(metrics.Registry.(*crprometheus.Registry)),
	)
	if err != nil {
		return err
	}

	meterProvider := metric.NewMeterProvider(metric.WithReader(exporter))
	global.SetMeterProvider(meterProvider)

	return nil
}
