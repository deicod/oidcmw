package observability

import (
	"context"
	"errors"
	"fmt"

	"github.com/deicod/oidcmw/config"
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics exposes Prometheus collectors for authentication outcomes.
type Metrics struct {
	requestTotal    *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// MetricsOptions configures Metrics construction.
type MetricsOptions struct {
	Registerer      prometheus.Registerer
	Namespace       string
	Subsystem       string
	DurationBuckets []float64
}

// NewMetrics constructs Metrics and registers the collectors with the provided registerer.
func NewMetrics(opts MetricsOptions) (*Metrics, error) {
	registerer := opts.Registerer
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}
	buckets := opts.DurationBuckets
	if buckets == nil {
		buckets = prometheus.DefBuckets
	}

	counter := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: opts.Namespace,
		Subsystem: opts.Subsystem,
		Name:      "requests_total",
		Help:      "Total number of OIDC authentication attempts.",
	}, []string{"issuer", "outcome", "error_code"})

	histogram := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: opts.Namespace,
		Subsystem: opts.Subsystem,
		Name:      "duration_seconds",
		Help:      "Duration of OIDC authentication attempts in seconds.",
		Buckets:   buckets,
	}, []string{"issuer", "outcome"})

	registeredCounter, err := registerCollector(registerer, counter)
	if err != nil {
		return nil, err
	}
	counterVec, ok := registeredCounter.(*prometheus.CounterVec)
	if !ok {
		return nil, fmt.Errorf("observability: requests_total collector has unexpected type %T", registeredCounter)
	}

	registeredHistogram, err := registerCollector(registerer, histogram)
	if err != nil {
		return nil, err
	}
	histogramVec, ok := registeredHistogram.(*prometheus.HistogramVec)
	if !ok {
		return nil, fmt.Errorf("observability: duration_seconds collector has unexpected type %T", registeredHistogram)
	}

	return &Metrics{requestTotal: counterVec, requestDuration: histogramVec}, nil
}

// RecordValidation implements config.MetricsRecorder.
func (m *Metrics) RecordValidation(_ context.Context, event config.MetricsEvent) {
	if m == nil {
		return
	}
	issuer := event.Issuer
	if issuer == "" {
		issuer = "unknown"
	}
	outcome := string(event.Outcome)
	if outcome == "" {
		outcome = string(config.MetricsOutcomeFailure)
	}
	errorCode := event.ErrorCode
	if errorCode == "" {
		errorCode = "none"
	}
	m.requestTotal.WithLabelValues(issuer, outcome, errorCode).Inc()
	m.requestDuration.WithLabelValues(issuer, outcome).Observe(event.Duration.Seconds())
}

func registerCollector(reg prometheus.Registerer, collector prometheus.Collector) (prometheus.Collector, error) {
	if reg == nil {
		return nil, errors.New("observability: registerer is nil")
	}
	if err := reg.Register(collector); err != nil {
		var are prometheus.AlreadyRegisteredError
		if errors.As(err, &are) {
			if are.ExistingCollector == nil {
				return nil, errors.New("observability: collector already registered but missing reference")
			}
			return are.ExistingCollector, nil
		}
		return nil, err
	}
	return collector, nil
}

// Collectors exposes the underlying collectors for advanced registration scenarios.
func (m *Metrics) Collectors() []prometheus.Collector {
	if m == nil {
		return nil
	}
	return []prometheus.Collector{m.requestTotal, m.requestDuration}
}
