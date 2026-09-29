package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus counters and histograms.
type Metrics struct {
	eventsTotal    *prometheus.CounterVec
	alertsTotal    *prometheus.CounterVec
	latencyHist    prometheus.Histogram
	collectorLines *prometheus.CounterVec
	evictions      *prometheus.CounterVec
	aiAnalyses     *prometheus.CounterVec
	aiDuration     *prometheus.HistogramVec
	registry       *prometheus.Registry
}

// NewMetrics registers and returns a new Metrics instance.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	eventsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "security_events_total",
		Help: "Total number of security events received, partitioned by event type.",
	}, []string{"event_type"})

	alertsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "security_alerts_total",
		Help: "Total number of alerts generated, partitioned by severity.",
	}, []string{"severity"})

	latencyHist := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "event_processing_duration_seconds",
		Help:    "End-to-end processing latency for a single event.",
		Buckets: prometheus.DefBuckets,
	})

	collectorLines := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "collector_lines_total",
		Help: "Total number of log lines processed by collectors, partitioned by collector and result.",
	}, []string{"collector", "result"})

	evictions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "storage_evictions_total",
		Help: "Total number of stored items dropped, partitioned by kind (event, alert) and reason (retention, capacity).",
	}, []string{"kind", "reason"})

	aiAnalyses := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ai_analyses_total",
		Help: "Total number of AI alert analyses, partitioned by provider and result (completed, failed, refused, skipped).",
	}, []string{"provider", "result"})

	aiDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ai_analysis_duration_seconds",
		Help:    "Duration of a single AI alert analysis.",
		Buckets: []float64{0.25, 0.5, 1, 2, 5, 10, 20, 30, 60},
	}, []string{"provider"})

	reg.MustRegister(eventsTotal, alertsTotal, latencyHist, collectorLines, evictions, aiAnalyses, aiDuration)

	return &Metrics{
		eventsTotal:    eventsTotal,
		alertsTotal:    alertsTotal,
		latencyHist:    latencyHist,
		collectorLines: collectorLines,
		evictions:      evictions,
		aiAnalyses:     aiAnalyses,
		aiDuration:     aiDuration,
		registry:       reg,
	}
}

// RecordEvent increments the events counter for the given event type.
func (m *Metrics) RecordEvent(eventType string) {
	m.eventsTotal.WithLabelValues(eventType).Inc()
}

// RecordAlert increments the alert counter for the given severity.
func (m *Metrics) RecordAlert(severity string) {
	m.alertsTotal.WithLabelValues(severity).Inc()
}

// RecordLatency observes the processing duration.
func (m *Metrics) RecordLatency(duration time.Duration) {
	m.latencyHist.Observe(duration.Seconds())
}

// Handler returns an HTTP handler that exposes the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// RecordCollectorLine counts a log line processed by a collector.
func (m *Metrics) RecordCollectorLine(collector, result string) {
	m.collectorLines.WithLabelValues(collector, result).Inc()
}

// RecordEviction counts n stored items dropped for the given kind and reason.
func (m *Metrics) RecordEviction(kind, reason string, n int) {
	m.evictions.WithLabelValues(kind, reason).Add(float64(n))
}

// ObserveStorage exposes the current storage size as gauges. stats is called on every scrape.
func (m *Metrics) ObserveStorage(stats func() (events, eventIPs, alerts int)) {
	gauge := func(name, help string, pick func(events, eventIPs, alerts int) int) prometheus.GaugeFunc {
		return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 {
			return float64(pick(stats()))
		})
	}
	m.registry.MustRegister(
		gauge("storage_events", "Number of events currently stored.",
			func(e, _, _ int) int { return e }),
		gauge("storage_event_ips", "Number of distinct source IPs among stored events.",
			func(_, ips, _ int) int { return ips }),
		gauge("storage_alerts", "Number of alerts currently stored.",
			func(_, _, a int) int { return a }),
	)
}

// RecordAIAnalysis counts an AI analysis and, unless it was skipped, its duration.
func (m *Metrics) RecordAIAnalysis(provider, result string, duration time.Duration) {
	m.aiAnalyses.WithLabelValues(provider, result).Inc()
	if duration > 0 {
		m.aiDuration.WithLabelValues(provider).Observe(duration.Seconds())
	}
}

// ObserveAIQueue exposes the number of alerts waiting for AI analysis.
func (m *Metrics) ObserveAIQueue(length func() int) {
	m.registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "ai_queue_length",
		Help: "Number of alerts waiting for AI analysis.",
	}, func() float64 { return float64(length()) }))
}
