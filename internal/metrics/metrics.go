package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

const (
	namespace = "nats_iam_broker"

	// Label names
	labelStatus  = "status"
	labelAccount = "account"
	labelIDP     = "idp"
	labelStage   = "stage"

	// Status values
	StatusSuccess = "success"
	StatusError   = "error"
	StatusDenied  = "denied"

	// Stage values for request errors
	StageDecrypt = "decrypt"
	StageDecode  = "decode"
	StageSign    = "sign"
	StageEncrypt = "encrypt"
)

// Metrics holds all prometheus metrics for the broker.
type Metrics struct {
	UserProjectionErrors *prometheus.CounterVec
	AuthRequestsTotal    *prometheus.CounterVec
	AuthRequestDuration  *prometheus.HistogramVec
	AuthRequestsInFlight prometheus.Gauge
	TokensMinted         *prometheus.CounterVec
	IDPVerifyTotal       *prometheus.CounterVec
	IDPVerifyDuration    *prometheus.HistogramVec
	RequestErrors        *prometheus.CounterVec
	ResponseErrors       *prometheus.CounterVec
}

// New creates and registers all prometheus metrics.
func New() *Metrics { return NewWithRegisterer(prometheus.DefaultRegisterer) }

// NewWithRegisterer isolates collectors for independently hosted broker instances.
func NewWithRegisterer(registerer prometheus.Registerer) *Metrics {
	m := &Metrics{
		UserProjectionErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Name: "user_projection_errors_total", Help: "Projection refusals by IdP and bounded error kind.",
		}, []string{labelIDP, "kind"}),
		AuthRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "auth_requests_total",
				Help:      "Total number of auth callout requests processed.",
			},
			[]string{labelStatus},
		),
		AuthRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "auth_request_duration_seconds",
				Help:      "Duration of auth callout request processing in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelStatus},
		),
		AuthRequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "auth_requests_in_flight",
				Help:      "Number of auth callout requests currently being processed.",
			},
		),
		TokensMinted: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "tokens_minted_total",
				Help:      "Total number of NATS user JWTs minted, by account and IDP.",
			},
			[]string{labelAccount, labelIDP},
		),
		IDPVerifyTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "idp_verify_total",
				Help:      "Total number of IDP JWT verification attempts.",
			},
			[]string{labelIDP, labelStatus},
		),
		IDPVerifyDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "idp_verify_duration_seconds",
				Help:      "Duration of IDP JWT verification in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{labelIDP},
		),
		RequestErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "request_errors_total",
				Help:      "Total request processing errors by stage (decrypt, decode).",
			},
			[]string{labelStage},
		),
		ResponseErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "response_errors_total",
				Help:      "Total response processing errors by stage (sign, encrypt).",
			},
			[]string{labelStage},
		),
	}

	registerer.MustRegister(
		m.UserProjectionErrors,
		m.AuthRequestsTotal,
		m.AuthRequestDuration,
		m.AuthRequestsInFlight,
		m.TokensMinted,
		m.IDPVerifyTotal,
		m.IDPVerifyDuration,
		m.RequestErrors,
		m.ResponseErrors,
	)

	return m
}

// Server runs an HTTP server that exposes the /metrics endpoint.
type Server struct {
	httpServer *http.Server
}

const (
	readHeaderTimeout = 5 * time.Second
	shutdownTimeout   = 5 * time.Second
)

// NewServer creates a new metrics HTTP server on the given port.
// If a HealthChecker is provided, /healthz and /readyz use it for
// real liveness and readiness checks; otherwise /healthz returns "ok".
func NewServer(port int, health *HealthChecker) *Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	if health != nil {
		mux.HandleFunc("/healthz", health.LivenessHandler())
		mux.HandleFunc("/readyz", health.ReadinessHandler())
	} else {
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
	}

	return &Server{
		httpServer: &http.Server{
			Addr:              fmt.Sprintf(":%d", port),
			Handler:           mux,
			ReadHeaderTimeout: readHeaderTimeout,
		},
	}
}

// Start begins listening in a goroutine. Returns immediately.
func (s *Server) Start() {
	go func() {
		zap.L().Info("metrics server listening", zap.String("addr", s.httpServer.Addr))
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.L().Error("metrics server error", zap.Error(err))
		}
	}()
}

// Stop gracefully shuts down the metrics server.
func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		zap.L().Error("metrics server shutdown error", zap.Error(err))
	}
}
