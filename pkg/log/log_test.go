package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := log.DefaultConfig()
	
	assert.Equal(t, log.LevelInfo, cfg.Level)
	assert.Equal(t, "json", cfg.Format)
	assert.NotNil(t, cfg.Writer)
	assert.False(t, cfg.AddSource)
	assert.Nil(t, cfg.ContextKeys)
}

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		config *log.Config
	}{
		{
			name:   "with nil config uses default",
			config: nil,
		},
		{
			name: "with json format",
			config: &log.Config{
				Level:     log.LevelDebug,
				Format:    "json",
				Writer:    &bytes.Buffer{},
				AddSource: true,
			},
		},
		{
			name: "with text format",
			config: &log.Config{
				Level:     log.LevelWarn,
				Format:    "text",
				Writer:    &bytes.Buffer{},
				AddSource: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := log.New(tt.config)
			assert.NotNil(t, logger)
			assert.NotNil(t, logger.Logger)
		})
	}
}

func TestLogger_WithField(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	// Create logger with field
	loggerWithField := logger.WithField("key", "value")
	loggerWithField.Info("test message")

	// Parse log output
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value", logEntry["key"])
}

func TestLogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	// Create logger with multiple fields
	fields := map[string]interface{}{
		"field1": "value1",
		"field2": 42,
		"field3": true,
	}
	loggerWithFields := logger.WithFields(fields)
	loggerWithFields.Info("test message")

	// Parse log output
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	assert.Equal(t, "test message", logEntry["msg"])
	assert.Equal(t, "value1", logEntry["field1"])
	assert.Equal(t, float64(42), logEntry["field2"]) // JSON unmarshals numbers as float64
	assert.Equal(t, true, logEntry["field3"])
}

func TestLogger_WithContext(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	ctx := context.Background()
	loggerWithCtx := logger.WithContext(ctx)
	assert.NotNil(t, loggerWithCtx)
	
	// Test that it returns a logger
	loggerWithCtx.Info("test message")
	
	// Verify log was written
	assert.NotEmpty(t, buf.String())
}

func TestLogger_Levels(t *testing.T) {
	tests := []struct {
		name        string
		logLevel    log.Level
		msgLevel    string
		shouldLog   bool
	}{
		{
			name:      "debug level logs debug",
			logLevel:  log.LevelDebug,
			msgLevel:  "debug",
			shouldLog: true,
		},
		{
			name:      "info level skips debug",
			logLevel:  log.LevelInfo,
			msgLevel:  "debug",
			shouldLog: false,
		},
		{
			name:      "info level logs info",
			logLevel:  log.LevelInfo,
			msgLevel:  "info",
			shouldLog: true,
		},
		{
			name:      "warn level logs warn",
			logLevel:  log.LevelWarn,
			msgLevel:  "warn",
			shouldLog: true,
		},
		{
			name:      "error level logs error",
			logLevel:  log.LevelError,
			msgLevel:  "error",
			shouldLog: true,
		},
		{
			name:      "error level skips warn",
			logLevel:  log.LevelError,
			msgLevel:  "warn",
			shouldLog: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := log.New(&log.Config{
				Level:  tt.logLevel,
				Format: "json",
				Writer: &buf,
			})

			msg := "test message"
			switch tt.msgLevel {
			case "debug":
				logger.Debug(msg)
			case "info":
				logger.Info(msg)
			case "warn":
				logger.Warn(msg)
			case "error":
				logger.Error(msg)
			}

			if tt.shouldLog {
				assert.NotEmpty(t, buf.String())
				// Verify the message was logged
				var logEntry map[string]interface{}
				err := json.Unmarshal(buf.Bytes(), &logEntry)
				require.NoError(t, err)
				assert.Equal(t, msg, logEntry["msg"])
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestLogger_TextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "text",
		Writer: &buf,
	})

	logger.Info("test message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key=value")
}

func TestLogger_AddSource(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:     log.LevelInfo,
		Format:    "json",
		Writer:    &buf,
		AddSource: true,
	})

	logger.Info("test message")

	// Parse log output
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)

	// Should have source information
	assert.Contains(t, logEntry, "source")
	source := logEntry["source"].(map[string]interface{})
	assert.Contains(t, source, "file")
	assert.Contains(t, source, "line")
}

func TestSetDefault(t *testing.T) {
	// Save original default logger
	originalDefault := log.Default()
	defer log.SetDefault(originalDefault)

	var buf bytes.Buffer
	newLogger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	log.SetDefault(newLogger)
	
	// Verify the default was set
	assert.Equal(t, newLogger, log.Default())
	
	// Test convenience functions use the new default
	log.Info("test from default")
	
	assert.NotEmpty(t, buf.String())
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)
	assert.Equal(t, "test from default", logEntry["msg"])
}

func TestConvenienceMethods(t *testing.T) {
	// Save original default logger
	originalDefault := log.Default()
	defer log.SetDefault(originalDefault)

	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelDebug,
		Format: "json",
		Writer: &buf,
	})
	log.SetDefault(logger)

	tests := []struct {
		name     string
		logFunc  func(string, ...interface{})
		level    string
	}{
		{
			name:    "debug",
			logFunc: log.Debug,
			level:   "DEBUG",
		},
		{
			name:    "info",
			logFunc: log.Info,
			level:   "INFO",
		},
		{
			name:    "warn",
			logFunc: log.Warn,
			level:   "WARN",
		},
		{
			name:    "error",
			logFunc: log.Error,
			level:   "ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			
			tt.logFunc("test message", "key", "value")
			
			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			require.NoError(t, err)
			
			assert.Equal(t, "test message", logEntry["msg"])
			assert.Equal(t, tt.level, logEntry["level"])
			assert.Equal(t, "value", logEntry["key"])
		})
	}
}

func TestGetLoggerFromContext(t *testing.T) {
	tests := []struct {
		name           string
		setupContext   func() context.Context
		expectDefault  bool
	}{
		{
			name: "context with logger",
			setupContext: func() context.Context {
				logger := log.New(&log.Config{
					Level:  log.LevelInfo,
					Format: "json",
					Writer: &bytes.Buffer{},
				})
				return log.ContextWithLogger(context.Background(), logger)
			},
			expectDefault: false,
		},
		{
			name: "context without logger",
			setupContext: func() context.Context {
				return context.Background()
			},
			expectDefault: true,
		},
		{
			name: "nil context",
			setupContext: func() context.Context {
				return nil
			},
			expectDefault: true,
		},
		{
			name: "context with wrong type",
			setupContext: func() context.Context {
				type wrongKey struct{}
				return context.WithValue(context.Background(), wrongKey{}, "not a logger")
			},
			expectDefault: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.setupContext()
			logger := log.GetLoggerFromContext(ctx)
			
			assert.NotNil(t, logger)
			if tt.expectDefault {
				assert.Equal(t, log.Default(), logger)
			} else {
				// Should be the logger from context, not default
				assert.NotNil(t, logger)
			}
		})
	}
}

func TestContextWithLogger(t *testing.T) {
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &bytes.Buffer{},
	})

	ctx := log.ContextWithLogger(context.Background(), logger)
	
	// Retrieve logger from context
	retrievedLogger := log.GetLoggerFromContext(ctx)
	assert.Equal(t, logger, retrievedLogger)
}

func TestLogger_WithFieldsEdgeCases(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	// Test with empty fields map
	emptyFields := map[string]interface{}{}
	loggerWithEmpty := logger.WithFields(emptyFields)
	loggerWithEmpty.Info("test empty fields")
	
	var logEntry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)
	assert.Equal(t, "test empty fields", logEntry["msg"])
	
	// Test with nil values
	buf.Reset()
	nilFields := map[string]interface{}{
		"nilField": nil,
		"strField": "value",
	}
	loggerWithNil := logger.WithFields(nilFields)
	loggerWithNil.Info("test nil fields")
	
	err = json.Unmarshal(buf.Bytes(), &logEntry)
	require.NoError(t, err)
	assert.Equal(t, "test nil fields", logEntry["msg"])
	assert.Nil(t, logEntry["nilField"])
	assert.Equal(t, "value", logEntry["strField"])
}

func TestLogger_OutputFormats(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		checkOutput    func(t *testing.T, output string)
	}{
		{
			name:   "json format with special characters",
			format: "json",
			checkOutput: func(t *testing.T, output string) {
				var logEntry map[string]interface{}
				err := json.Unmarshal([]byte(output), &logEntry)
				require.NoError(t, err)
				assert.Equal(t, "test \"quoted\" message", logEntry["msg"])
				assert.Equal(t, "value with\nnewline", logEntry["special"])
			},
		},
		{
			name:   "text format with special characters",
			format: "text",
			checkOutput: func(t *testing.T, output string) {
				assert.Contains(t, output, "test \\\"quoted\\\" message")
				assert.Contains(t, output, "special=\"value with\\nnewline\"")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := log.New(&log.Config{
				Level:  log.LevelInfo,
				Format: tt.format,
				Writer: &buf,
			})

			logger.Info("test \"quoted\" message", "special", "value with\nnewline")
			
			tt.checkOutput(t, strings.TrimSpace(buf.String()))
		})
	}
}

func TestLogger_ConcurrentUse(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&log.Config{
		Level:  log.LevelInfo,
		Format: "json",
		Writer: &buf,
	})

	done := make(chan bool, 10)
	
	// Launch multiple goroutines logging concurrently
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.WithField("goroutine", id).Info("concurrent log")
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all logs were written
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 10)
	
	// Verify each line is valid JSON
	for _, line := range lines {
		var logEntry map[string]interface{}
		err := json.Unmarshal([]byte(line), &logEntry)
		require.NoError(t, err)
		assert.Equal(t, "concurrent log", logEntry["msg"])
		assert.Contains(t, logEntry, "goroutine")
	}
}