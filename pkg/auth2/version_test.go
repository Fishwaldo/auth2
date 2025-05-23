package auth2_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/auth2"
	"github.com/stretchr/testify/assert"
)

func TestGetVersion(t *testing.T) {
	version := auth2.GetVersion()
	assert.Equal(t, auth2.Version, version)
	assert.NotEmpty(t, version)
}

func TestVersionInfo(t *testing.T) {
	info := auth2.VersionInfo()
	
	// Check that all expected components are present
	assert.Contains(t, info, "auth2 version")
	assert.Contains(t, info, auth2.Version)
	assert.Contains(t, info, "Git commit:")
	assert.Contains(t, info, auth2.GitCommit)
	assert.Contains(t, info, "Built on:")
	assert.Contains(t, info, auth2.BuildDate)
	assert.Contains(t, info, "Go version:")
	assert.Contains(t, info, runtime.Version())
	
	// Check format
	lines := strings.Split(info, "\n")
	assert.Len(t, lines, 4)
	
	// Check each line starts correctly
	assert.True(t, strings.HasPrefix(lines[0], "auth2 version"))
	assert.True(t, strings.HasPrefix(lines[1], "Git commit:"))
	assert.True(t, strings.HasPrefix(lines[2], "Built on:"))
	assert.True(t, strings.HasPrefix(lines[3], "Go version:"))
}

func TestVersionVariables(t *testing.T) {
	// Test default values
	assert.Equal(t, "0.1.0", auth2.Version)
	assert.Equal(t, "unknown", auth2.GitCommit)
	assert.Equal(t, "unknown", auth2.BuildDate)
	assert.Equal(t, runtime.Version(), auth2.GoVersion)
	
	// Go version should not be "unknown"
	assert.NotEqual(t, "unknown", auth2.GoVersion)
	assert.True(t, strings.HasPrefix(auth2.GoVersion, "go"))
}

// Test that version variables can be overridden at build time
func TestVersionOverride(t *testing.T) {
	// Save original values
	origVersion := auth2.Version
	origCommit := auth2.GitCommit
	origDate := auth2.BuildDate
	
	// Override values
	auth2.Version = "1.2.3"
	auth2.GitCommit = "abc123"
	auth2.BuildDate = "2024-01-01"
	
	// Test with overridden values
	assert.Equal(t, "1.2.3", auth2.GetVersion())
	
	info := auth2.VersionInfo()
	assert.Contains(t, info, "1.2.3")
	assert.Contains(t, info, "abc123")
	assert.Contains(t, info, "2024-01-01")
	
	// Restore original values
	auth2.Version = origVersion
	auth2.GitCommit = origCommit
	auth2.BuildDate = origDate
}