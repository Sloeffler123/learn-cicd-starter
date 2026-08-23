package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key != "my-secret-key" {
		t.Errorf("expected key 'my-secret-key', got '%s'", key)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got: %v", err)
	}
}

func TestGetAPIKey_MalformedHeader_NoKey(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestGetAPIKey_MalformedHeader_WrongScheme(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer my-secret-key")

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
}
