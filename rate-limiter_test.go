package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRateLimiter_Middleware(t *testing.T) {
	// Criar uma instância do RateLimiter
	limiter := NewRateLimiter(DefaultConfig)

	// Criar um handler de teste
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Test response"))
	})

	// Criar um request de teste com IP e token
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("API_KEY", "test_token")

	// Criar um ResponseWriter de teste
	rr := httptest.NewRecorder()

	// Chamar o middleware
	limiter.Middleware(handler).ServeHTTP(rr, req)

	// Verificar o código de status
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler retornou código de status errado: esperado %v, recebido %v", http.StatusOK, status)
	}

	// Verificar o corpo da resposta
	expected := "Test response"
	if rr.Body.String() != expected {
		t.Errorf("Handler retornou corpo de resposta errado: esperado %v, recebido %v", expected, rr.Body.String())
	}
}

func TestRateLimiter_Integration(t *testing.T) {
	// Configurar o RateLimiter
	limiter := NewRateLimiter(DefaultConfig)
	limiter.SetTokenRateLimit("test_token", DefaultConfig)

	// Iniciar o servidor HTTP de teste
	server := httptest.NewServer(limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Test response"))
	})))
	defer server.Close()

	// Criar um client HTTP para enviar solicitações para o servidor de teste
	client := &http.Client{}

	// Enviar várias solicitações para testar os limites
	for i := 0; i < 105; i++ {
		req, err := http.NewRequest("GET", server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("API_KEY", "test_token")
		_, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Verificar se o servidor respondeu conforme o esperado
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Esperado status de erro 429, recebido %d", resp.StatusCode)
	}
}
