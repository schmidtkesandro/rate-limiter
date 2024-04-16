package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"golang.org/x/time/rate"
)

func TestRateLimiterMiddleware(t *testing.T) {
	// Cria um servidor HTTP de teste com o middleware do Rate Limiter
	limiter := createTestRateLimiter()
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(limiter.Middleware)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})
	//t.Errorf("-1-------------------------------")
	// Teste para requisição dentro do limite
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:1234" // IP válido
	req.Header.Set("API_KEY", "")       // Token inválido
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("1 Request should be allowed but got status code %d e %d", resp.Code, http.StatusOK)
	}
	//t.Errorf("-2----------------------------")
	// Teste para requisição excedendo o limite de IP
	resp1 := http.StatusOK
	for i := 0; i < 20; i++ {
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		resp1 = resp.Code
	}
	if resp1 != http.StatusTooManyRequests {
		t.Errorf("2 Request should be blocked due to IP rate limit but got status code %d e %d", resp.Code, http.StatusTooManyRequests)
	}
	//t.Errorf("-3-------------------------------")
	// Teste para requisição excedendo o limite de token
	req.RemoteAddr = "192.168.1.0:1234"      // IP válido
	req.Header.Set("API_KEY", "valid_token") // Token válido
	resp = httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Errorf("3 Request should be blocked due to token rate limit but got status code %d e %d", resp.Code, http.StatusTooManyRequests)
	}
	// Teste para requisição excedendo o limite de Token
	resp1 = http.StatusOK
	for i := 0; i < 20; i++ {
		resp = httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		resp1 = resp.Code
	}
	if resp1 != http.StatusTooManyRequests {
		t.Errorf("4 Request should be blocked due to token rate limit but got status code %d e %d", resp.Code, http.StatusTooManyRequests)
	}
}

// createTestRateLimiter cria um RateLimiter com configurações para teste
func createTestRateLimiter() *RateLimiter {
	return &RateLimiter{
		Config: Config{
			MaxRequests:      10,              // Limite de requisições por segundo
			IPBlockPeriod:    1 * time.Minute, // Período de bloqueio para IPs
			TokenBlockPeriod: 1 * time.Minute, // Período de bloqueio para tokens
		},
		IPRateLimiters:  make(map[string]*rate.Limiter),
		TokenRateLimits: make(map[string]TokenRateLimit),
		IPBlockList:     make(map[string]time.Time),
		TokenBlockList:  make(map[string]time.Time),
		TokenConfigs:    make(map[string]Config),
	}
}
