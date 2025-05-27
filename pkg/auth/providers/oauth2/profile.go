package oauth2

import (
	"fmt"
)

// GoogleProfileMapping maps Google user data to UserInfo
func GoogleProfileMapping(data map[string]interface{}) (*UserInfo, error) {
	userInfo := &UserInfo{
		ProviderName: "google",
		Raw:          data,
	}
	
	if id, ok := data["id"].(string); ok {
		userInfo.ID = id
		userInfo.ProviderID = id
	} else if sub, ok := data["sub"].(string); ok {
		userInfo.ID = sub
		userInfo.ProviderID = sub
	}
	
	if email, ok := data["email"].(string); ok {
		userInfo.Email = email
	}
	
	if verified, ok := data["email_verified"].(bool); ok {
		userInfo.EmailVerified = verified
	} else if verified, ok := data["verified_email"].(bool); ok {
		userInfo.EmailVerified = verified
	}
	
	if name, ok := data["name"].(string); ok {
		userInfo.Name = name
	}
	
	if givenName, ok := data["given_name"].(string); ok {
		userInfo.GivenName = givenName
	}
	
	if familyName, ok := data["family_name"].(string); ok {
		userInfo.FamilyName = familyName
	}
	
	if picture, ok := data["picture"].(string); ok {
		userInfo.Picture = picture
	}
	
	if locale, ok := data["locale"].(string); ok {
		userInfo.Locale = locale
	}
	
	return userInfo, nil
}

// GitHubProfileMapping maps GitHub user data to UserInfo
func GitHubProfileMapping(data map[string]interface{}) (*UserInfo, error) {
	userInfo := &UserInfo{
		ProviderName: "github",
		Raw:          data,
	}
	
	if id, ok := data["id"].(float64); ok {
		userInfo.ID = fmt.Sprintf("%.0f", id)
		userInfo.ProviderID = userInfo.ID
	}
	
	if email, ok := data["email"].(string); ok {
		userInfo.Email = email
		userInfo.EmailVerified = true // GitHub verifies emails
	}
	
	if name, ok := data["name"].(string); ok {
		userInfo.Name = name
	} else if login, ok := data["login"].(string); ok {
		userInfo.Name = login
	}
	
	if avatarURL, ok := data["avatar_url"].(string); ok {
		userInfo.Picture = avatarURL
	}
	
	return userInfo, nil
}

// MicrosoftProfileMapping maps Microsoft user data to UserInfo
func MicrosoftProfileMapping(data map[string]interface{}) (*UserInfo, error) {
	userInfo := &UserInfo{
		ProviderName: "microsoft",
		Raw:          data,
	}
	
	if id, ok := data["id"].(string); ok {
		userInfo.ID = id
		userInfo.ProviderID = id
	}
	
	if email, ok := data["mail"].(string); ok {
		userInfo.Email = email
		userInfo.EmailVerified = true // Microsoft verifies emails
	} else if upn, ok := data["userPrincipalName"].(string); ok {
		userInfo.Email = upn
		userInfo.EmailVerified = true
	}
	
	if name, ok := data["displayName"].(string); ok {
		userInfo.Name = name
	}
	
	if givenName, ok := data["givenName"].(string); ok {
		userInfo.GivenName = givenName
	}
	
	if surname, ok := data["surname"].(string); ok {
		userInfo.FamilyName = surname
	}
	
	return userInfo, nil
}

// FacebookProfileMapping maps Facebook user data to UserInfo
func FacebookProfileMapping(data map[string]interface{}) (*UserInfo, error) {
	userInfo := &UserInfo{
		ProviderName: "facebook",
		Raw:          data,
	}
	
	if id, ok := data["id"].(string); ok {
		userInfo.ID = id
		userInfo.ProviderID = id
	}
	
	if email, ok := data["email"].(string); ok {
		userInfo.Email = email
		userInfo.EmailVerified = true // Facebook verifies emails
	}
	
	if name, ok := data["name"].(string); ok {
		userInfo.Name = name
	}
	
	if firstName, ok := data["first_name"].(string); ok {
		userInfo.GivenName = firstName
	}
	
	if lastName, ok := data["last_name"].(string); ok {
		userInfo.FamilyName = lastName
	}
	
	// Facebook picture is nested
	if picture, ok := data["picture"].(map[string]interface{}); ok {
		if pictureData, ok := picture["data"].(map[string]interface{}); ok {
			if url, ok := pictureData["url"].(string); ok {
				userInfo.Picture = url
			}
		}
	}
	
	return userInfo, nil
}

// DefaultProfileMapping provides a generic mapping for unknown providers
func DefaultProfileMapping(data map[string]interface{}) (*UserInfo, error) {
	userInfo := &UserInfo{
		Raw: data,
	}
	
	// Try common field names
	for _, idField := range []string{"id", "ID", "sub", "user_id", "userId"} {
		if id, ok := data[idField].(string); ok {
			userInfo.ID = id
			userInfo.ProviderID = id
			break
		}
	}
	
	for _, emailField := range []string{"email", "Email", "mail", "email_address"} {
		if email, ok := data[emailField].(string); ok {
			userInfo.Email = email
			break
		}
	}
	
	for _, nameField := range []string{"name", "Name", "display_name", "displayName", "full_name"} {
		if name, ok := data[nameField].(string); ok {
			userInfo.Name = name
			break
		}
	}
	
	for _, pictureField := range []string{"picture", "avatar", "avatar_url", "profile_image", "photo"} {
		if picture, ok := data[pictureField].(string); ok {
			userInfo.Picture = picture
			break
		}
	}
	
	return userInfo, nil
}