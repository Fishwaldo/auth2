package user_test

import (
	"testing"

	"github.com/Fishwaldo/auth2/pkg/user"
)

func TestSimple(t *testing.T) {
	// Just a simple test to verify we can import and use the user package
	u := &user.User{
		ID: "test",
		Username: "test",
	}
	
	if u.ID != "test" {
		t.Errorf("Expected ID to be test, got %s", u.ID)
	}
}
