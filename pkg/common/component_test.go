package common_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/Fishwaldo/auth2/pkg/common"
)

// TestComponentLifecycle tests the component lifecycle functionality
func TestComponentLifecycle(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test initial state
	if component.GetID() != "test-component" {
		t.Errorf("GetID() = %v, want \"test-component\"", component.GetID())
	}
	
	if component.GetName() != "Test Component" {
		t.Errorf("GetName() = %v, want \"Test Component\"", component.GetName())
	}
	
	if component.GetDescription() != "A test component for testing" {
		t.Errorf("GetDescription() = %v, want \"A test component for testing\"", component.GetDescription())
	}
	
	if component.GetVersion() != "1.0.0" {
		t.Errorf("GetVersion() = %v, want \"1.0.0\"", component.GetVersion())
	}
	
	if component.IsRunning() {
		t.Errorf("IsRunning() = true, want false")
	}
	
	// Test starting the component
	ctx := context.Background()
	err := component.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	
	if !component.IsRunning() {
		t.Errorf("IsRunning() = false, want true")
	}
	
	// Test starting an already running component
	err = component.Start(ctx)
	if err == nil {
		t.Errorf("Start() error = nil, want error")
	}
	
	// Test stopping the component
	err = component.Stop(ctx)
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	
	if component.IsRunning() {
		t.Errorf("IsRunning() = true, want false")
	}
	
	// Test stopping an already stopped component
	err = component.Stop(ctx)
	if err == nil {
		t.Errorf("Stop() error = nil, want error")
	}
}

// TestComponentDependencies tests the component dependency functionality
func TestComponentDependencies(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test with no dependencies
	err := component.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	
	// Clean up
	_ = component.Stop(context.Background())
	
	// Add a required dependency
	dependency := common.NewComponent(
		"dep-component",
		"Dependency Component",
		"A dependency component",
		"1.0.0",
	)
	
	component.AddDependency("dep1", "component", true, dependency)
	
	// Test getting dependency
	dep, ok := component.GetDependency("dep1")
	if !ok {
		t.Fatalf("GetDependency() not found")
	}
	
	if dep != dependency {
		t.Errorf("GetDependency() = %v, want %v", dep, dependency)
	}
	
	// Test getting non-existent dependency
	_, ok = component.GetDependency("non-existent")
	if ok {
		t.Errorf("GetDependency() found, want not found")
	}
	
	// Add a nil required dependency
	component.AddDependency("dep2", "component", true, nil)
	
	// Test starting with missing dependency
	err = component.Start(context.Background())
	if err == nil {
		t.Errorf("Start() error = nil, want error")
	}
}

// TestComponentFeatures tests the component feature functionality
func TestComponentFeatures(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test with no features
	if len(component.GetFeatures()) != 0 {
		t.Errorf("GetFeatures() length = %v, want 0", len(component.GetFeatures()))
	}
	
	if component.Supports(common.FeatureTracing) {
		t.Errorf("Supports() = true, want false")
	}
	
	// Add features
	component.AddFeature(common.FeatureTracing)
	component.AddFeature(common.FeatureMetrics)
	
	// Test with features
	features := component.GetFeatures()
	if len(features) != 2 {
		t.Fatalf("GetFeatures() length = %v, want 2", len(features))
	}
	
	featureMap := make(map[string]bool)
	for _, f := range features {
		featureMap[f] = true
	}
	
	if !featureMap[common.FeatureTracing] {
		t.Errorf("GetFeatures() missing %v", common.FeatureTracing)
	}
	
	if !featureMap[common.FeatureMetrics] {
		t.Errorf("GetFeatures() missing %v", common.FeatureMetrics)
	}
	
	if !component.Supports(common.FeatureTracing) {
		t.Errorf("Supports(%v) = false, want true", common.FeatureTracing)
	}
	
	if !component.Supports(common.FeatureMetrics) {
		t.Errorf("Supports(%v) = false, want true", common.FeatureMetrics)
	}
	
	if component.Supports(common.FeatureLogging) {
		t.Errorf("Supports(%v) = true, want false", common.FeatureLogging)
	}
	
	// Remove a feature
	component.RemoveFeature(common.FeatureTracing)
	
	if component.Supports(common.FeatureTracing) {
		t.Errorf("Supports(%v) = true, want false after removal", common.FeatureTracing)
	}
	
	if !component.Supports(common.FeatureMetrics) {
		t.Errorf("Supports(%v) = false, want true", common.FeatureMetrics)
	}
}

// TestComponentMetrics tests the component metrics functionality
func TestComponentMetrics(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test with no metrics
	_, ok := component.GetMetric("requests")
	if ok {
		t.Errorf("GetMetric() found, want not found")
	}
	
	// Set metrics
	component.SetMetric("requests", 100)
	component.SetMetric("errors", 5)
	
	// Get metrics
	requests, ok := component.GetMetric("requests")
	if !ok {
		t.Fatalf("GetMetric() not found, want found")
	}
	
	if requests != 100 {
		t.Errorf("GetMetric() = %v, want 100", requests)
	}
	
	errors, ok := component.GetMetric("errors")
	if !ok {
		t.Fatalf("GetMetric() not found, want found")
	}
	
	if errors != 5 {
		t.Errorf("GetMetric() = %v, want 5", errors)
	}
	
	// Update a metric
	component.SetMetric("requests", 200)
	
	requests, ok = component.GetMetric("requests")
	if !ok {
		t.Fatalf("GetMetric() not found, want found")
	}
	
	if requests != 200 {
		t.Errorf("GetMetric() = %v, want 200", requests)
	}
}

// TestComponentConfiguration tests the component configuration functionality
func TestComponentConfiguration(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test with no configuration
	if component.GetConfig() != nil {
		t.Errorf("GetConfig() = %v, want nil", component.GetConfig())
	}
	
	// Set configuration
	type TestConfig struct {
		Name    string
		Enabled bool
		Timeout int
	}
	
	config := TestConfig{
		Name:    "Test",
		Enabled: true,
		Timeout: 30,
	}
	
	err := component.Configure(config)
	if err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	
	// Get configuration
	configResult := component.GetConfig()
	if configResult == nil {
		t.Fatalf("GetConfig() = nil, want non-nil")
	}
	
	configTyped, ok := configResult.(TestConfig)
	if !ok {
		t.Fatalf("GetConfig() type assertion failed")
	}
	
	if configTyped.Name != "Test" {
		t.Errorf("GetConfig().Name = %v, want \"Test\"", configTyped.Name)
	}
	
	if !configTyped.Enabled {
		t.Errorf("GetConfig().Enabled = %v, want true", configTyped.Enabled)
	}
	
	if configTyped.Timeout != 30 {
		t.Errorf("GetConfig().Timeout = %v, want 30", configTyped.Timeout)
	}
}

// TestComponentHealthCheck tests the component health check functionality
func TestComponentHealthCheck(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Test health check when not running
	err := component.HealthCheck(context.Background())
	if err == nil {
		t.Errorf("HealthCheck() error = nil, want error")
	}
	
	// Test status when not running
	status, err := component.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	
	if status.Code != common.StatusCritical {
		t.Errorf("Status().Code = %v, want %v", status.Code, common.StatusCritical)
	}
	
	// Start the component
	err = component.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	
	// Test health check when running
	err = component.HealthCheck(context.Background())
	if err != nil {
		t.Errorf("HealthCheck() error = %v, want nil", err)
	}
	
	// Test status when running
	status, err = component.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	
	if status.Code != common.StatusOK {
		t.Errorf("Status().Code = %v, want %v", status.Code, common.StatusOK)
	}
}

// TestComponentDispose tests the component dispose functionality
func TestComponentDispose(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Start the component
	err := component.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	
	// Verify running
	if !component.IsRunning() {
		t.Errorf("IsRunning() = false, want true")
	}
	
	// Dispose the component
	err = component.Dispose(context.Background())
	if err != nil {
		t.Fatalf("Dispose() error = %v", err)
	}
	
	// Verify stopped
	if component.IsRunning() {
		t.Errorf("IsRunning() = true, want false")
	}
}

// TestComponentDebugInfo tests the component debug info functionality
func TestComponentDebugInfo(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Add features and metrics
	component.AddFeature(common.FeatureTracing)
	component.SetMetric("requests", 100)
	
	// Get debug info
	info, err := component.GetDebugInfo(context.Background())
	if err != nil {
		t.Fatalf("GetDebugInfo() error = %v", err)
	}
	
	// Verify debug info
	if info["id"] != "test-component" {
		t.Errorf("GetDebugInfo()[\"id\"] = %v, want \"test-component\"", info["id"])
	}
	
	if info["name"] != "Test Component" {
		t.Errorf("GetDebugInfo()[\"name\"] = %v, want \"Test Component\"", info["name"])
	}
	
	if info["version"] != "1.0.0" {
		t.Errorf("GetDebugInfo()[\"version\"] = %v, want \"1.0.0\"", info["version"])
	}
	
	if info["running"] != false {
		t.Errorf("GetDebugInfo()[\"running\"] = %v, want false", info["running"])
	}
	
	// Check metrics
	metrics, ok := info["metrics"].(map[string]interface{})
	if !ok {
		t.Fatalf("GetDebugInfo()[\"metrics\"] type assertion failed")
	}
	
	if metrics["requests"] != 100 {
		t.Errorf("GetDebugInfo()[\"metrics\"][\"requests\"] = %v, want 100", metrics["requests"])
	}
	
	// Check features
	features, ok := info["features"].([]string)
	if !ok {
		t.Fatalf("GetDebugInfo()[\"features\"] type assertion failed")
	}
	
	if len(features) != 1 || features[0] != common.FeatureTracing {
		t.Errorf("GetDebugInfo()[\"features\"] = %v, want [%v]", features, common.FeatureTracing)
	}
	
	// Start the component
	err = component.Start(context.Background())
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	
	// Get debug info again
	info, err = component.GetDebugInfo(context.Background())
	if err != nil {
		t.Fatalf("GetDebugInfo() error = %v", err)
	}
	
	// Verify runtime info
	if info["running"] != true {
		t.Errorf("GetDebugInfo()[\"running\"] = %v, want true", info["running"])
	}
	
	if _, ok := info["uptime"]; !ok {
		t.Errorf("GetDebugInfo()[\"uptime\"] missing")
	}
	
	if _, ok := info["started"]; !ok {
		t.Errorf("GetDebugInfo()[\"started\"] missing")
	}
}

// nilWriter is a writer that discards all writes
type nilWriter struct{}

func (nilWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// TestComponentLogger tests the component logger functionality
func TestComponentLogger(t *testing.T) {
	// Create a component
	component := common.NewComponent(
		"test-component",
		"Test Component",
		"A test component for testing",
		"1.0.0",
	)
	
	// Create a custom logger
	logger := slog.New(slog.NewTextHandler(nilWriter{}, nil))
	
	// Set the logger
	component.SetLogger(logger)
	
	// No assertion needed, just make sure it doesn't panic
}