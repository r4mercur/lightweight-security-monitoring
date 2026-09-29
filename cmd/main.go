package main

import (
	"context"
	"errors"
	"fmt"
	"lightweight-security-monitoring/internal/ai"
	"lightweight-security-monitoring/internal/api"
	"lightweight-security-monitoring/internal/collector"
	"lightweight-security-monitoring/internal/domain"
	"lightweight-security-monitoring/internal/metrics"
	"lightweight-security-monitoring/internal/repository"
	"lightweight-security-monitoring/internal/service"
	"lightweight-security-monitoring/pkg/logger"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	// Embedded time zone database: the scratch image has none, but syslog and
	// Windows Firewall timestamps are in local time and need TZ to be honoured.
	_ "time/tzdata"
)

func main() {
	log := logger.New(slog.LevelInfo)

	// ── Configuration from environment ──────────────────────────────────────
	addr := envOr("ADDR", ":8080")
	apiKeys := strings.Split(os.Getenv("API_KEYS"), ",")
	storage, err := storageConfigFromEnv()
	if err != nil {
		log.Error("invalid storage configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}
	aiCfg, err := ai.ConfigFromEnv(os.Getenv)
	if err != nil {
		log.Error("invalid AI configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}
	analysisCfg, err := analysisConfigFromEnv()
	if err != nil {
		log.Error("invalid AI configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ── Infrastructure ───────────────────────────────────────────────────────
	m := metrics.NewMetrics()
	store := repository.NewMemoryStore(
		repository.WithRetention(storage.eventRetention, storage.alertRetention),
		repository.WithCapacity(storage.maxEvents, storage.maxAlerts),
		repository.WithEvictionFunc(m.RecordEviction),
	)
	m.ObserveStorage(func() (int, int, int) {
		s := store.Stats()
		return s.Events, s.EventIPs, s.Alerts
	})
	analyzer, err := ai.New(aiCfg)
	if err != nil {
		log.Error("invalid AI configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ── Service layer ────────────────────────────────────────────────────────
	rules, rulesSource, err := loadRules(os.Getenv("RULES_FILE"))
	if err != nil {
		log.Error("loading detection rules failed", slog.String("error", err.Error()))
		os.Exit(1)
	}
	engine, err := service.NewDetectionEngine(rules)
	if err != nil {
		log.Error("invalid detection rules", slog.String("error", err.Error()))
		os.Exit(1)
	}
	log.Info("detection rules loaded", slog.String("source", rulesSource), slog.Int("rules", rules.Len()))

	// Cooldowns and correlation read the alert history; it must not be pruned earlier.
	if lookback := engine.AlertLookback(); storage.alertRetention > 0 && storage.alertRetention < lookback {
		log.Error("ALERT_RETENTION is shorter than the longest rule cooldown / correlation window",
			slog.String("alert_retention", storage.alertRetention.String()), slog.String("required", lookback.String()))
		os.Exit(1)
	}
	log.Info("storage configured",
		slog.String("event_retention", storage.eventRetention.String()), slog.Int("max_events", storage.maxEvents),
		slog.String("alert_retention", storage.alertRetention.String()), slog.Int("max_alerts", storage.maxAlerts),
	)

	// AI analysis runs in a background queue; nil disables it.
	var (
		analysis service.AlertAnalysis
		queue    *service.AnalysisQueue
	)
	if analyzer != nil {
		queue, err = service.NewAnalysisQueue(analyzer, store, analysisCfg, m, log)
		if err != nil {
			log.Error("invalid AI configuration", slog.String("error", err.Error()))
			os.Exit(1)
		}
		m.ObserveAIQueue(queue.Len)
		analysis = queue
		log.Info("AI analysis enabled",
			slog.String("provider", analyzer.Provider()), slog.String("model", analyzer.Model()),
			slog.Int("workers", analysisCfg.Workers), slog.Int("queue_size", analysisCfg.QueueSize),
			slog.String("min_severity", string(analysisCfg.MinSeverity)),
		)
	} else {
		log.Warn("AI analysis disabled - set AI_PROVIDER, OPENAI_API_KEY or ANTHROPIC_API_KEY to enable it")
	}

	ingestion := service.NewIngestionService(store, store, engine, analysis, m, log)

	// ── Collectors ───────────────────────────────────────────────────────────
	collectors, err := loadCollectors(os.Getenv("COLLECTORS_FILE"), ingestion, m, log)
	if err != nil {
		log.Error("loading collectors failed", slog.String("error", err.Error()))
		os.Exit(1)
	}

	// ── API layer ────────────────────────────────────────────────────────────
	auth := api.NewAPIKeyAuth(apiKeys)
	if !auth.Enabled() {
		log.Warn("API_KEYS not set – event and alert endpoints are unauthenticated")
	}
	handler := api.NewHandler(ingestion, store, store, log)
	router := api.SetupRoutes(handler, m, auth)

	// ── Run until SIGINT/SIGTERM ─────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup
	if queue != nil {
		wg.Go(func() { queue.Run(ctx) })
	}
	wg.Go(func() {
		runJanitor(ctx, janitorInterval, func(now time.Time) {
			store.Prune(now)
			engine.Prune(now)
		})
	})
	srv := &http.Server{
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second, // batch requests may take up to 25 s
		IdleTimeout:  60 * time.Second,
	}

	// Listen before starting the collectors, so the connection collector's
	// baseline already contains our own port instead of reporting it as new.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error("listening failed", slog.String("addr", addr), slog.String("error", err.Error()))
		os.Exit(1)
	}
	go func() {
		log.Info("server listening", slog.String("addr", ln.Addr().String()))
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", slog.String("error", err.Error()))
			os.Exit(1)
		}
	}()

	for _, c := range collectors {
		wg.Go(func() {
			if err := c.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("collector stopped", slog.String("collector", c.Name()), slog.String("error", err.Error()))
			}
		})
	}

	<-ctx.Done()

	log.Info("shutting down server...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("forced shutdown", slog.String("error", err.Error()))
	}
	wg.Wait()
	log.Info("server stopped")
}

// loadRules reads the rule file at path, or the embedded default rules when path is empty.
func loadRules(path string) (service.RuleSet, string, error) {
	if path == "" {
		rules, err := service.DefaultRules()
		return rules, "embedded defaults", err
	}
	rules, err := service.LoadRulesFile(path)
	return rules, path, err
}

// loadCollectors builds the collectors from the file at path. No path means no collectors.
func loadCollectors(path string, sink collector.Sink, rec collector.LineRecorder, log *slog.Logger) ([]collector.Collector, error) {
	if path == "" {
		return nil, nil
	}
	cfg, err := collector.LoadConfigFile(path)
	if err != nil {
		return nil, err
	}
	collectors, err := collector.Build(cfg, sink, rec, log)
	if err != nil {
		return nil, err
	}
	log.Info("collectors loaded", slog.String("source", path), slog.Int("collectors", len(collectors)))
	return collectors, nil
}

// janitorInterval is how often expired events, alerts and rule state are released.
const janitorInterval = time.Minute

func runJanitor(ctx context.Context, interval time.Duration, prune func(now time.Time)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			prune(now.UTC())
		}
	}
}

type storageConfig struct {
	eventRetention, alertRetention time.Duration
	maxEvents, maxAlerts           int
}

// storageConfigFromEnv reads EVENT_RETENTION, ALERT_RETENTION, MAX_EVENTS and
// MAX_ALERTS. A value of 0 disables the respective limit.
func storageConfigFromEnv() (storageConfig, error) {
	var (
		cfg  storageConfig
		errs []error
	)
	duration := func(key string, def time.Duration) time.Duration {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			errs = append(errs, fmt.Errorf("%s: %q is not a valid non-negative duration (e.g. 24h)", key, v))
		}
		return d
	}
	integer := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			errs = append(errs, fmt.Errorf("%s: %q is not a valid non-negative integer", key, v))
		}
		return n
	}

	cfg.eventRetention = duration("EVENT_RETENTION", repository.DefaultEventRetention)
	cfg.alertRetention = duration("ALERT_RETENTION", repository.DefaultAlertRetention)
	cfg.maxEvents = integer("MAX_EVENTS", repository.DefaultMaxEvents)
	cfg.maxAlerts = integer("MAX_ALERTS", repository.DefaultMaxAlerts)
	return cfg, errors.Join(errs...)
}

// analysisConfigFromEnv reads AI_WORKERS, AI_QUEUE_SIZE and AI_MIN_SEVERITY.
func analysisConfigFromEnv() (service.AnalysisConfig, error) {
	cfg := service.AnalysisConfig{Workers: 2, QueueSize: 100, MinSeverity: domain.SeverityLow}
	var errs []error
	for key, dst := range map[string]*int{"AI_WORKERS": &cfg.Workers, "AI_QUEUE_SIZE": &cfg.QueueSize} {
		if v := os.Getenv(key); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				errs = append(errs, fmt.Errorf("%s: %q must be a positive integer", key, v))
				continue
			}
			*dst = n
		}
	}
	if v := os.Getenv("AI_MIN_SEVERITY"); v != "" {
		cfg.MinSeverity = domain.Severity(strings.ToLower(v))
		if !cfg.MinSeverity.Valid() {
			errs = append(errs, fmt.Errorf("AI_MIN_SEVERITY: %q must be low, medium, high or critical", v))
		}
	}
	return cfg, errors.Join(errs...)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
