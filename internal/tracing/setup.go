// Package tracing provides OpenTelemetry TracerProvider setup and trace context utilities.
package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/contrib/bridges/otelzap"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// zapErrorHandler routes OTel SDK internal errors to the zap logger
// instead of silently discarding them.
type zapErrorHandler struct{}

func (zapErrorHandler) Handle(err error) {
	zap.L().Error("OTel SDK error", zap.Error(err))
}

// Result holds the outputs of Setup.
type Result struct {
	// Shutdown flushes and shuts down all OTel providers.
	Shutdown func(context.Context) error
	// ZapCore is a zapcore.Core that bridges zap logs to OTel Logs SDK.
	// Nil when tracing/logging is disabled.
	ZapCore zapcore.Core
}

// Setup initialises the OTel TracerProvider and LoggerProvider.
//
// Exporter selection:
//   - OTEL_EXPORTER_OTLP_ENDPOINT set → OTLP gRPC exporter
//   - OTEL_TRACES_EXPORTER=console   → stdout (pretty-printed, for local dev)
//   - Neither set                    → tracing disabled (no-op)
//
// Sampling is controlled via the OTEL_TRACES_SAMPLER env var (SDK default: always_on).
func Setup(ctx context.Context, serviceName, serviceVersion string) (*Result, error) {
	otel.SetErrorHandler(zapErrorHandler{})

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	tracesExporter := os.Getenv("OTEL_TRACES_EXPORTER")

	// If no exporter is configured, tracing is disabled — return a no-op.
	if endpoint == "" && tracesExporter != "console" {
		zap.L().Info("OTel tracing disabled (set OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_TRACES_EXPORTER=console to enable)")
		noop := func(context.Context) error { return nil }
		return &Result{Shutdown: noop}, nil
	}

	environment := os.Getenv("OTEL_DEPLOYMENT_ENVIRONMENT")

	attrs := []resource.Option{
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
			semconv.TelemetrySDKLanguageGo,
		),
	}
	if environment != "" {
		attrs = append(attrs, resource.WithAttributes(
			semconv.DeploymentEnvironmentKey.String(environment),
		))
	}

	res, err := resource.New(ctx, attrs...)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTel resource: %w", err)
	}

	// --- Traces ---
	var spanExporter sdktrace.SpanExporter
	if endpoint != "" {
		spanExporter, err = otlptracegrpc.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP trace exporter: %w", err)
		}
		zap.L().Info("OTel tracing configured", zap.String("exporter", "otlp-grpc"), zap.String("endpoint", endpoint))
	} else {
		spanExporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout trace exporter: %w", err)
		}
		zap.L().Info("OTel tracing configured", zap.String("exporter", "console"))
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(spanExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// --- Logs ---
	var lp *log.LoggerProvider
	var zapCore zapcore.Core
	if endpoint != "" {
		logExporter, logErr := otlploggrpc.New(ctx)
		if logErr != nil {
			zap.L().Warn("failed to create OTLP log exporter, logs will not be sent to collector", zap.Error(logErr))
		} else {
			lp = log.NewLoggerProvider(
				log.WithProcessor(log.NewBatchProcessor(logExporter)),
				log.WithResource(res),
			)
			otel.SetLoggerProvider(lp)
			zapCore = otelzap.NewCore(serviceName, otelzap.WithLoggerProvider(lp))
			zap.L().Info("OTel logging configured", zap.String("exporter", "otlp-grpc"))
		}
	}

	shutdown := func(ctx context.Context) error {
		var errs []error
		if err := tp.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider: %w", err))
		}
		if lp != nil {
			if err := lp.Shutdown(ctx); err != nil {
				errs = append(errs, fmt.Errorf("log provider: %w", err))
			}
		}
		if len(errs) > 0 {
			return fmt.Errorf("OTel shutdown errors: %v", errs)
		}
		return nil
	}

	return &Result{Shutdown: shutdown, ZapCore: zapCore}, nil
}

// SetupWithExporter initialises a TracerProvider with the given exporter,
// bypassing env-var detection. Intended for testing.
func SetupWithExporter(ctx context.Context, serviceName, serviceVersion string, exporter sdktrace.SpanExporter) (func(context.Context) error, error) {
	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(serviceName),
		semconv.ServiceVersion(serviceVersion),
		semconv.TelemetrySDKLanguageGo,
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
