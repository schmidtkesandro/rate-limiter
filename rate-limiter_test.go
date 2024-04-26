package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestCheckRateLimit(t *testing.T) {
	limiter := RateLimiter{
		Config: Config{
			MaxRequests:      2,
			IPBlockPeriod:    time.Minute,
			TokenBlockPeriod: time.Minute,
		},
		TokenConfigs: map[string]TokenConfig{
			"default": {
				MaxRequests:      1,
				IPBlockPeriod:    time.Minute,
				TokenBlockPeriod: time.Minute,
			},
		},
	}

	ip := "127.0.0.1"
	token := ""

	// Teste limite de IP
	if err := limiter.CheckRateLimit(ip, token); err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Teste limite de token
	limiter.TokenLimits = map[string]*rate.Limiter{"test": rate.NewLimiter(rate.Limit(1), 1)}
	token = "test"
	if err := limiter.CheckRateLimit(ip, token); err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	// Teste limite excedido de token
	if err := limiter.CheckRateLimit(ip, token); err == nil {
		t.Errorf("Expected error, got nil")
	}
}

func TestMiddleware(t *testing.T) {
	limiter := RateLimiter{
		Config: Config{
			MaxRequests:      2,
			IPBlockPeriod:    time.Minute,
			TokenBlockPeriod: time.Minute,
		},
		TokenConfigs: map[string]TokenConfig{
			"default": {
				MaxRequests:      1,
				IPBlockPeriod:    time.Minute,
				TokenBlockPeriod: time.Minute,
			},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	// Teste limite de IP
	limiter.Middleware(handler).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Teste limite de token
	r.Header.Set("API_KEY", "test")
	w = httptest.NewRecorder()
	limiter.TokenLimits = map[string]*rate.Limiter{"test": rate.NewLimiter(rate.Limit(1), 1)}
	limiter.Middleware(handler).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Teste limite excedido de token
	w = httptest.NewRecorder()
	limiter.Middleware(handler).ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status code %d, got %d", http.StatusTooManyRequests, w.Code)
	}
}
