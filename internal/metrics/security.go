package security

import (
	"github.com/goletan/observability/pkg"
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct{}

var (
	// Events is a Prometheus counter vector that tracks security-library-related events-service, such as failed authentications.
	Events = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "goletan",
			Subsystem: "security-library",
			Name:      "events_count",
			Help:      "Counts security-library-related events-service like failed authentications.",
		},
		[]string{"event_type", "service", "severity"},
	)
)

// InitMetrics registers the Metrics with the observability-library manager.
func InitMetrics(observer *observability.Observability) {
	observer.Metrics.Register(&Metrics{})
}

// Register registers the Metrics instance with the Prometheus package. It returns an error if registration fails.
func (em *Metrics) Register() error {
	if err := prometheus.Register(Events); err != nil {
		return err
	}

	return nil
}

// RecordSecurityEvent logs a security-library event with specified type, service, and severity, and increments the event counter.
func RecordSecurityEvent(eventType, service, severity string) {
	Events.WithLabelValues(eventType, service, severity).Inc()
}
