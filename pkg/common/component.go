package common

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Component provides a base implementation of common interfaces
type Component struct {
	// ID is the unique identifier for the component
	ID string
	
	// Name is the human-readable name of the component
	Name string
	
	// Description is a description of the component
	Description string
	
	// Version is the version of the component
	Version string
	
	// Config is the component configuration
	Config interface{}
	
	// Logger is the component logger
	Logger *slog.Logger
	
	// Running indicates if the component is running
	Running bool
	
	// runningMu is a mutex for the Running flag
	runningMu sync.Mutex
	
	// startTime is the time the component was started
	startTime time.Time
	
	// metrics contains component metrics
	metrics map[string]interface{}
	
	// metricsMu is a mutex for the metrics map
	metricsMu sync.RWMutex
	
	// features contains supported features
	features map[string]bool
	
	// dependencies contains component dependencies
	dependencies []Dependency
}

// Dependency represents a component dependency
type Dependency struct {
	// ID is the unique identifier for the dependency
	ID string
	
	// Type is the dependency type
	Type string
	
	// Required indicates if the dependency is required
	Required bool
	
	// Component is the dependency component
	Component interface{}
}

// NewComponent creates a new component
func NewComponent(id, name, description, version string) *Component {
	return &Component{
		ID:           id,
		Name:         name,
		Description:  description,
		Version:      version,
		Logger:       slog.Default().With("component", id),
		Running:      false,
		metrics:      make(map[string]interface{}),
		features:     make(map[string]bool),
		dependencies: make([]Dependency, 0),
	}
}

// GetID returns the component ID
func (c *Component) GetID() string {
	return c.ID
}

// GetName returns the component name
func (c *Component) GetName() string {
	return c.Name
}

// GetDescription returns the component description
func (c *Component) GetDescription() string {
	return c.Description
}

// GetVersion returns the component version
func (c *Component) GetVersion() string {
	return c.Version
}

// Configure configures the component
func (c *Component) Configure(config interface{}) error {
	c.Config = config
	return nil
}

// GetConfig returns the component configuration
func (c *Component) GetConfig() interface{} {
	return c.Config
}

// Start starts the component
func (c *Component) Start(ctx context.Context) error {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	
	if c.Running {
		return fmt.Errorf("component %s is already running", c.ID)
	}
	
	// Check dependencies
	if err := c.checkDependencies(); err != nil {
		return err
	}
	
	c.Running = true
	c.startTime = time.Now()
	
	c.Logger.Info("component started", "id", c.ID, "version", c.Version)
	
	return nil
}

// Stop stops the component
func (c *Component) Stop(ctx context.Context) error {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	
	if !c.Running {
		return fmt.Errorf("component %s is not running", c.ID)
	}
	
	c.Running = false
	
	c.Logger.Info("component stopped", "id", c.ID, "uptime", time.Since(c.startTime))
	
	return nil
}

// IsRunning returns true if the component is running
func (c *Component) IsRunning() bool {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	
	return c.Running
}

// HealthCheck performs a health check
func (c *Component) HealthCheck(ctx context.Context) error {
	if !c.IsRunning() {
		return fmt.Errorf("component is not running")
	}
	
	return nil
}

// Status returns the component status
func (c *Component) Status(ctx context.Context) (Status, error) {
	if !c.IsRunning() {
		return Status{
			Code:    StatusCritical,
			Message: "component is not running",
			Details: map[string]interface{}{
				"component": c.ID,
				"uptime":    0,
			},
		}, nil
	}
	
	return Status{
		Code:    StatusOK,
		Message: "component is running",
		Details: map[string]interface{}{
			"component": c.ID,
			"uptime":    time.Since(c.startTime).String(),
			"started":   c.startTime,
		},
	}, nil
}

// GetDebugInfo returns component debug information
func (c *Component) GetDebugInfo(ctx context.Context) (map[string]interface{}, error) {
	c.metricsMu.RLock()
	defer c.metricsMu.RUnlock()
	
	info := map[string]interface{}{
		"id":          c.ID,
		"name":        c.Name,
		"description": c.Description,
		"version":     c.Version,
		"running":     c.IsRunning(),
		"metrics":     c.metrics,
		"features":    c.GetFeatures(),
	}
	
	if c.IsRunning() {
		info["uptime"] = time.Since(c.startTime).String()
		info["started"] = c.startTime
	}
	
	return info, nil
}

// Dispose disposes the component
func (c *Component) Dispose(ctx context.Context) error {
	if c.IsRunning() {
		if err := c.Stop(ctx); err != nil {
			return err
		}
	}
	
	c.Logger.Info("component disposed", "id", c.ID)
	
	return nil
}

// Supports checks if the component supports a specific feature
func (c *Component) Supports(feature string) bool {
	supported, ok := c.features[feature]
	return ok && supported
}

// GetFeatures returns all supported features
func (c *Component) GetFeatures() []string {
	var features []string
	
	for feature, supported := range c.features {
		if supported {
			features = append(features, feature)
		}
	}
	
	return features
}

// AddFeature adds a supported feature
func (c *Component) AddFeature(feature string) {
	c.features[feature] = true
}

// RemoveFeature removes a supported feature
func (c *Component) RemoveFeature(feature string) {
	delete(c.features, feature)
}

// SetLogger sets the component logger
func (c *Component) SetLogger(logger *slog.Logger) {
	c.Logger = logger.With("component", c.ID)
}

// SetMetric sets a component metric
func (c *Component) SetMetric(name string, value interface{}) {
	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()
	
	c.metrics[name] = value
}

// GetMetric gets a component metric
func (c *Component) GetMetric(name string) (interface{}, bool) {
	c.metricsMu.RLock()
	defer c.metricsMu.RUnlock()
	
	value, ok := c.metrics[name]
	return value, ok
}

// AddDependency adds a component dependency
func (c *Component) AddDependency(id, depType string, required bool, component interface{}) {
	c.dependencies = append(c.dependencies, Dependency{
		ID:        id,
		Type:      depType,
		Required:  required,
		Component: component,
	})
}

// GetDependency gets a component dependency
func (c *Component) GetDependency(id string) (interface{}, bool) {
	for _, dep := range c.dependencies {
		if dep.ID == id {
			return dep.Component, true
		}
	}
	
	return nil, false
}

// checkDependencies checks that all required dependencies are available
func (c *Component) checkDependencies() error {
	for _, dep := range c.dependencies {
		if dep.Required && dep.Component == nil {
			return fmt.Errorf("required dependency %s of type %s is missing", dep.ID, dep.Type)
		}
	}
	
	return nil
}