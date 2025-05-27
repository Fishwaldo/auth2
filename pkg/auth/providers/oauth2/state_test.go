package oauth2_test

import (
	"context"
	"testing"
	"time"

	"github.com/Fishwaldo/auth2/pkg/auth/providers/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestStateManager_CreateState(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	stateManager := oauth2.NewStateManager(mockStore, 10*time.Minute, "test-provider")

	tests := []struct {
		name        string
		redirectURI string
		extra       map[string]string
		setupMocks  func()
		wantErr     bool
	}{
		{
			name:        "create state successfully",
			redirectURI: "http://localhost/callback",
			extra:       map[string]string{"prompt": "consent"},
			setupMocks: func() {
				mockStore.On("StoreState", ctx, "oauth2_state", "test-provider", mock.MatchedBy(func(state string) bool {
					return len(state) == 32
				}), mock.Anything).Return(nil).Once()
			},
			wantErr: false,
		},
		{
			name:        "store error",
			redirectURI: "http://localhost/callback",
			setupMocks: func() {
				mockStore.On("StoreState", ctx, "oauth2_state", "test-provider", mock.Anything, mock.Anything).
					Return(assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ExpectedCalls = nil
			mockStore.Calls = nil
			
			if tt.setupMocks != nil {
				tt.setupMocks()
			}
			
			state, err := stateManager.CreateState(ctx, tt.redirectURI, tt.extra)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, state)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, state)
				assert.Len(t, state, 32) // Expected length after encoding
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}

func TestStateManager_ValidateState(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	stateManager := oauth2.NewStateManager(mockStore, 10*time.Minute, "test-provider")

	tests := []struct {
		name       string
		state      string
		setupMocks func()
		want       *oauth2.StateData
		wantErr    error
	}{
		{
			name:  "empty state",
			state: "",
			wantErr: oauth2.ErrInvalidState,
		},
		{
			name:  "state not found",
			state: "test-state",
			setupMocks: func() {
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "test-state", mock.Anything).
					Return(assert.AnError).Once()
			},
			wantErr: oauth2.ErrStateNotFound,
		},
		{
			name:  "expired state",
			state: "test-state",
			setupMocks: func() {
				expiredState := &oauth2.StateData{
					State:       "test-state",
					RedirectURI: "http://localhost/callback",
					CreatedAt:   time.Now().Add(-20 * time.Minute),
					ExpiresAt:   time.Now().Add(-10 * time.Minute),
				}
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "test-state", mock.Anything).
					Run(func(args mock.Arguments) {
						ptr := args.Get(4).(*oauth2.StateData)
						*ptr = *expiredState
					}).Return(nil).Once()
				
				mockStore.On("DeleteState", ctx, "oauth2_state", "test-provider", "test-state").Return(nil).Once()
			},
			wantErr: oauth2.ErrStateExpired,
		},
		{
			name:  "valid state",
			state: "test-state",
			setupMocks: func() {
				validState := &oauth2.StateData{
					State:       "test-state",
					RedirectURI: "http://localhost/callback",
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Extra:       map[string]string{"prompt": "consent"},
				}
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "test-state", mock.Anything).
					Run(func(args mock.Arguments) {
						ptr := args.Get(4).(*oauth2.StateData)
						*ptr = *validState
					}).Return(nil).Once()
				
				mockStore.On("DeleteState", ctx, "oauth2_state", "test-provider", "test-state").Return(nil).Once()
			},
			want: &oauth2.StateData{
				State:       "test-state",
				RedirectURI: "http://localhost/callback",
				Extra:       map[string]string{"prompt": "consent"},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ExpectedCalls = nil
			mockStore.Calls = nil
			
			if tt.setupMocks != nil {
				tt.setupMocks()
			}
			
			got, err := stateManager.ValidateState(ctx, tt.state)
			
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, tt.want.State, got.State)
				assert.Equal(t, tt.want.RedirectURI, got.RedirectURI)
				assert.Equal(t, tt.want.Extra, got.Extra)
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}

func TestStateManager_CleanupExpiredStates(t *testing.T) {
	ctx := context.Background()
	mockStore := new(MockStateStore)
	
	stateManager := oauth2.NewStateManager(mockStore, 10*time.Minute, "test-provider")

	tests := []struct {
		name       string
		setupMocks func()
		wantErr    bool
	}{
		{
			name: "cleanup expired states",
			setupMocks: func() {
				// Mock listing keys
				keys := []string{"state1", "state2", "state3"}
				mockStore.On("ListStateKeys", ctx, "oauth2_state", "test-provider").
					Return(keys, nil).Once()
				
				// Mock getting state data
				// State 1: expired
				expiredState := &oauth2.StateData{
					ExpiresAt: time.Now().Add(-10 * time.Minute),
				}
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "state1", mock.Anything).
					Run(func(args mock.Arguments) {
						ptr := args.Get(4).(*oauth2.StateData)
						*ptr = *expiredState
					}).Return(nil).Once()
				mockStore.On("DeleteState", ctx, "oauth2_state", "test-provider", "state1").Return(nil).Once()
				
				// State 2: valid
				validState := &oauth2.StateData{
					ExpiresAt: time.Now().Add(10 * time.Minute),
				}
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "state2", mock.Anything).
					Run(func(args mock.Arguments) {
						ptr := args.Get(4).(*oauth2.StateData)
						*ptr = *validState
					}).Return(nil).Once()
				
				// State 3: error reading (skip)
				mockStore.On("GetState", ctx, "oauth2_state", "test-provider", "state3", mock.Anything).
					Return(assert.AnError).Once()
			},
			wantErr: false,
		},
		{
			name: "error listing keys",
			setupMocks: func() {
				mockStore.On("ListStateKeys", ctx, "oauth2_state", "test-provider").
					Return([]string{}, assert.AnError).Once()
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore.ExpectedCalls = nil
			mockStore.Calls = nil
			
			if tt.setupMocks != nil {
				tt.setupMocks()
			}
			
			err := stateManager.CleanupExpiredStates(ctx)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			
			mockStore.AssertExpectations(t)
		})
	}
}