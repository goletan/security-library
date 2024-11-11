// /security/internal/metrics/security.go
package security

import (
	observability "github.com/goletan/observability/pkg"
	"github.com/prometheus/client_golang/prometheus"
)

type SecurityMetrics struct{}

// Security Metrics: Track security events
var (
	SecurityEvents = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "goletan",
			Subsystem: "security",
			Name:      "events_count",
			Help:      "Counts security-related events like failed authentications.",
		},
		[]string{"event_type", "service", "severity"},
	)
)

func InitMetrics(observer *observability.Observability) {
	observer.Metrics.Register(&SecurityMetrics{})
}

func (em *SecurityMetrics) Register() error {
	if err := prometheus.Register(SecurityEvents); err != nil {
		return err
	}

	return nil
}

// RecordSecurityEvent records a security-related event.
func RecordSecurityEvent(eventType, service, severity string) {
	SecurityEvents.WithLabelValues(eventType, service, severity).Inc()
}
