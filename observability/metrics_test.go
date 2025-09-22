package observability

import (
	"context"
	"testing"
	"time"

	"github.com/deicod/oidcmw/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestMetricsRecordValidation(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewMetrics(MetricsOptions{Registerer: registry, Namespace: "oidcmw"})
	require.NoError(t, err)

	metrics.RecordValidation(context.Background(), config.MetricsEvent{
		Issuer:   "https://issuer",
		Outcome:  config.MetricsOutcomeSuccess,
		Duration: 150 * time.Millisecond,
	})
	metrics.RecordValidation(context.Background(), config.MetricsEvent{
		Issuer:    "https://issuer",
		Outcome:   config.MetricsOutcomeFailure,
		ErrorCode: "invalid_token",
		Duration:  200 * time.Millisecond,
	})

	success := testutil.ToFloat64(metrics.requestTotal.WithLabelValues("https://issuer", string(config.MetricsOutcomeSuccess), "none"))
	require.Equal(t, 1.0, success)

	failure := testutil.ToFloat64(metrics.requestTotal.WithLabelValues("https://issuer", string(config.MetricsOutcomeFailure), "invalid_token"))
	require.Equal(t, 1.0, failure)

	// Ensure histogram observations are recorded.
	count := testutil.CollectAndCount(metrics.requestDuration, "oidcmw_duration_seconds")
	require.Greater(t, count, 0)
}

func TestMetricsRegistersCollectors(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewMetrics(MetricsOptions{Registerer: registry})
	require.NoError(t, err)

	metrics.RecordValidation(context.Background(), config.MetricsEvent{Outcome: config.MetricsOutcomeSuccess})

	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 2)
}
