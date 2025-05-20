package log

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Level defines the logging level
type Level = slog.Level

// Predefined logging levels
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger wraps slog.Logger to provide a consistent logging interface
type Logger struct {
	*slog.Logger
}

// Config holds the configuration for the logger
type Config struct {
	Level       Level
	Format      string // "json" or "text"
	Writer      io.Writer
	AddSource   bool
	ContextKeys []string
}

// DefaultConfig returns the default logging configuration
func DefaultConfig() *Config {
	return &Config{
		Level:     LevelInfo,
		Format:    "json",
		Writer:    os.Stderr,
		AddSource: false,
	}
}

// New creates a new Logger with the given configuration
func New(cfg *Config) *Logger {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	var handler slog.Handler

	handlerOpts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	if cfg.Format == "json" {
		handler = slog.NewJSONHandler(cfg.Writer, handlerOpts)
	} else {
		handler = slog.NewTextHandler(cfg.Writer, handlerOpts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// WithContext adds context values to the logger
func (l *Logger) WithContext(ctx context.Context) *Logger {
	logger := l.Logger

	// Extract values from context and add them to the logger
	// This can be expanded to include specific context keys
	// based on the application's needs
	
	return &Logger{
		Logger: logger,
	}
}

// WithField adds a field to the logger
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		Logger: l.Logger.With(key, value),
	}
}

// WithFields adds multiple fields to the logger
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	logger := l.Logger
	
	for k, v := range fields {
		logger = logger.With(k, v)
	}
	
	return &Logger{
		Logger: logger,
	}
}

// Global default logger
var defaultLogger = New(DefaultConfig())

// SetDefault sets the default logger
func SetDefault(logger *Logger) {
	defaultLogger = logger
	slog.SetDefault(logger.Logger)
}

// Default returns the default logger
func Default() *Logger {
	return defaultLogger
}

// GetLoggerFromContext retrieves a logger from the context
// If no logger is found in the context, the default logger is returned
func GetLoggerFromContext(ctx context.Context) *Logger {
	if ctx == nil {
		return defaultLogger
	}
	
	// Check for logger in context
	if loggerValue := ctx.Value(loggerKey{}); loggerValue != nil {
		if logger, ok := loggerValue.(*Logger); ok {
			return logger
		}
	}
	
	return defaultLogger
}

// loggerKey is used as the key for storing the logger in the context
type loggerKey struct{}

// ContextWithLogger returns a new context with the logger
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// Convenience methods to use the default logger
func Debug(msg string, args ...interface{}) {
	defaultLogger.Debug(msg, args...)
}

func Info(msg string, args ...interface{}) {
	defaultLogger.Info(msg, args...)
}

func Warn(msg string, args ...interface{}) {
	defaultLogger.Warn(msg, args...)
}

func Error(msg string, args ...interface{}) {
	defaultLogger.Error(msg, args...)
}