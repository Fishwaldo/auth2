package bruteforce_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Fishwaldo/auth2/pkg/security/bruteforce"
)

func Example_newProtectionManager() {
	// Create storage implementation (using in-memory for this example)
	storage := bruteforce.NewMemoryStorage()

	// Create a mock notification service for this example
	notification := bruteforce.NewMockNotificationService()

	// Create configuration with custom settings
	config := bruteforce.DefaultConfig()
	config.MaxAttempts = 3
	config.LockoutDuration = 15 * time.Minute
	config.IPRateLimit = 10
	config.IPRateLimitWindow = 5 * time.Minute

	// Create the protection manager
	manager := bruteforce.NewProtectionManager(storage, config, notification)

	// Create integration helper
	authIntegration := bruteforce.NewAuthIntegration(manager)

	// Example usage in an authentication flow
	ctx := context.Background()
	userID := "user123"
	username := "testuser"
	ipAddress := "192.168.1.100"
	providerID := "basic"

	// Check before authentication
	err := authIntegration.CheckBeforeAuthentication(ctx, userID, username, ipAddress, providerID)
	if err != nil {
		// Handle locked or rate limited account
		log.Printf("Authentication blocked: %v", err)
		return
	}

	// Simulate authentication (in a real system, this would be your actual auth logic)
	authSuccessful := true // Simulating successful authentication

	// Record the attempt
	err = authIntegration.RecordAuthenticationAttempt(
		ctx,
		userID,
		username,
		ipAddress,
		providerID,
		authSuccessful,
		map[string]string{"device": "web", "browser": "chrome"},
	)
	if err != nil {
		log.Printf("Failed to record authentication attempt: %v", err)
	}

	// Simulate failed authentication attempts
	for i := 0; i < 3; i++ {
		err = authIntegration.RecordAuthenticationAttempt(
			ctx,
			userID,
			username,
			ipAddress,
			providerID,
			false, // Failed authentication
			map[string]string{"device": "web", "browser": "chrome"},
		)
		if err != nil {
			log.Printf("Failed to record authentication attempt: %v", err)
		}
	}

	// Check authentication again - account should be locked now
	err = authIntegration.CheckBeforeAuthentication(ctx, userID, username, ipAddress, providerID)
	if err != nil {
		// This should be an AccountLockedError
		log.Printf("Authentication blocked after failures: %v", err)
	}

	// Manually unlock the account
	err = manager.UnlockAccount(ctx, userID)
	if err != nil {
		log.Printf("Failed to unlock account: %v", err)
	}

	// Clean up
	manager.Stop()
}

func Example_newNotificationManager() {
	// Create storage
	storage := bruteforce.NewMemoryStorage()

	// Create a mock user service
	userService := bruteforce.NewMockUserService()
	userService.AddUser("user123", "user@example.com")

	// Create a mock email sender
	emailSender := bruteforce.NewMockEmailSender()

	// Create email notification config
	emailConfig := bruteforce.DefaultEmailConfig()
	emailConfig.FromAddress = "security@example.com"

	// Create notification config
	notificationConfig := bruteforce.DefaultNotificationConfig()
	notificationConfig.EmailConfig = emailConfig

	// Create notification manager
	notificationManager := bruteforce.NewNotificationManager(
		userService,
		emailSender,
		notificationConfig,
	)

	// Create protection manager config
	protectionConfig := bruteforce.DefaultConfig()
	protectionConfig.EmailNotification = true

	// Create protection manager
	manager := bruteforce.NewProtectionManager(storage, protectionConfig, notificationManager)

	// Create integration helper
	authIntegration := bruteforce.NewAuthIntegration(manager)

	// Context
	ctx := context.Background()

	// Now use it in your authentication flow
	userID := "user123"
	username := "testuser"
	ipAddress := "192.168.1.100"
	providerID := "basic"

	// Simulate failed authentication attempts to trigger lockout
	for i := 0; i < 5; i++ {
		err := authIntegration.RecordAuthenticationAttempt(
			ctx,
			userID,
			username,
			ipAddress,
			providerID,
			false, // Failed authentication
			map[string]string{"device": "web", "browser": "chrome"},
		)
		if err != nil {
			log.Printf("Failed to record authentication attempt: %v", err)
		}
	}

	// Account should be locked now, check for notification
	emails := emailSender.GetSentEmails()
	if len(emails) > 0 {
		fmt.Printf("Email notification sent to: %s\n", emails[0].To)
	}

	// Clean up
	manager.Stop()
}

func Example_newProvider() {
	// Create storage
	storage := bruteforce.NewMemoryStorage()

	// Create notification service
	notification := bruteforce.NewMockNotificationService()

	// Create config
	config := bruteforce.DefaultConfig()

	// Create provider
	provider := bruteforce.NewProvider(storage, config, notification)

	// Initialize the provider
	err := provider.Initialize(context.Background(), nil)
	if err != nil {
		log.Fatalf("Failed to initialize provider: %v", err)
	}

	// Get protection manager from provider
	manager := provider.GetProtectionManager()

	// Get auth integration from provider
	authIntegration := provider.GetAuthIntegration()

	// Use the auth integration
	ctx := context.Background()
	userID := "user123"
	username := "testuser"
	ipAddress := "192.168.1.100"
	providerID := "basic"

	// Check before authentication
	err = authIntegration.CheckBeforeAuthentication(ctx, userID, username, ipAddress, providerID)
	if err != nil {
		log.Printf("Authentication blocked: %v", err)
	} else {
		log.Printf("Authentication allowed")
	}

	// Get account lock history
	lockHistory, err := manager.GetLockHistory(ctx, userID)
	if err != nil {
		log.Printf("Failed to get lock history: %v", err)
	} else {
		log.Printf("Lock history size: %d", len(lockHistory))
	}

	// Stop the provider when done
	provider.Stop()
}