package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_Middleware(t *testing.T) {
	// Configurações do rate limiter para os testes
	cfg := Config{
		MaxRequests:      2,
		IPBlockPeriod:    1 * time.Second,
		TokenBlockPeriod: 1 * time.Second,
	}

	// Cria um novo rate limiter
	limiter := NewRateLimiter(cfg)

	// Configuração do servidor Gin para os testes
	router := gin.New()
	router.Use(limiter.Middleware())

	// Rota de teste
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "Test")
	})

	// Teste de solicitação dentro do limite
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Teste de solicitação excedendo o limite por IP
	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest("GET", "/test", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Teste de solicitação excedendo o limite por Token
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("API_KEY", "test_token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("API_KEY", "test_token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("API_KEY", "test_token")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
