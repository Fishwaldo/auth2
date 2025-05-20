package auth2

import (
	"fmt"
	"runtime"
)

// Version information
var (
	// Version is the current version of the auth2 library
	Version = "0.1.0"
	
	// GitCommit is the git commit hash at build time
	GitCommit = "unknown"
	
	// BuildDate is the date the binary was built
	BuildDate = "unknown"
	
	// GoVersion is the Go version used to compile the binary
	GoVersion = runtime.Version()
)

// VersionInfo returns a formatted string with version information
func VersionInfo() string {
	return fmt.Sprintf(
		"auth2 version %s\nGit commit: %s\nBuilt on: %s\nGo version: %s",
		Version,
		GitCommit,
		BuildDate,
		GoVersion,
	)
}

// GetVersion returns the current version
func GetVersion() string {
	return Version
}