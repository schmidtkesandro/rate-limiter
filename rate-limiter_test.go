package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"golang.org/x/time/rate"
)

func TestRateLimiterMiddleware(t *testing.T) {
	limiter := &RateLimiter{
		Config: Config{
			MaxRequests:      2,
			IPBlockPeriod:    5 * time.Second,
			TokenBlockPeriod: 5 * time.Second,
		},
		IPRateLimiters: make(map[string]*rate.Limiter),
		TokenLimits:    make(map[string]TokenConfig),
		BlockedIPs:     make(map[string]time.Time),
		BlockedTokens:  make(map[string]time.Time),
	}

	r := chi.NewRouter()
	r.Use(limiter.Middleware)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	tests := []struct {
		name         string
		requests     int
		expectedCode int
	}{
		{"BelowLimit", 1, http.StatusOK},
		{"AboveLimit", 3, http.StatusTooManyRequests},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < test.requests; i++ {
				resp := httptest.NewRecorder()
				r.ServeHTTP(resp, req)
				if resp.Code != test.expectedCode {
					t.Errorf("Expected status code %d; got %d", test.expectedCode, resp.Code)
				}
			}
		})
	}
}

// package main

// import (
// 	"net/http"
// 	"net/http/httptest"
// 	"testing"
// 	"time"

// 	"golang.org/x/time/rate"
// )

// func TestRateLimiterMiddleware(t *testing.T) {
// 	// Configuração padrão
// 	defaultConfig := Config{
// 		MaxRequests:      12,              // Limite de 2 requisições por segundo
// 		IPBlockPeriod:    5 * time.Minute, // Período de bloqueio para IPs: 5 minutos
// 		TokenBlockPeriod: 5 * time.Minute, // Período de bloqueio para tokens: 5 minutos
// 	}

// 	// Inicializa o Rate Limiter
// 	limiter := &RateLimiter{
// 		Config:         defaultConfig,
// 		IPRateLimiters: make(map[string]*rate.Limiter),
// 		TokenLimits:    make(map[string]TokenConfig),
// 		BlockedIPs:     make(map[string]time.Time),
// 		BlockedTokens:  make(map[string]time.Time),
// 	}

// 	// Configura um servidor de teste com o middleware do rate limiter
// 	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		w.Write([]byte("OK"))
// 	})
// 	testServer := httptest.NewServer(limiter.Middleware(handler))
// 	defer testServer.Close()

// 	// Cria um cliente HTTP para o servidor de teste
// 	client := &http.Client{}

// 	// Testa com uma requisição válida
// 	req, err := http.NewRequest("GET", testServer.URL, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	resp, err := client.Do(req)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
// 	}

// 	// Testa com uma segunda requisição válida
// 	resp, err = client.Do(req)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusOK {
// 		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
// 	}

// 	// Testa com uma terceira requisição inválida (deve retornar 429 - Too Many Requests)
// 	resp, err = client.Do(req)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != http.StatusTooManyRequests {
// 		t.Errorf("Expected status code %d, got %d", http.StatusTooManyRequests, resp.StatusCode)
// 	}
// }
