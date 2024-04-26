package main

import (
	"testing"
	"time"

	"github.com/sandroschmidtke/go/ratelimiter"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_LimitByIP(t *testing.T) {
	// Configuração do rate limiter com limite de 5 requisições por segundo por IP
	limiter := ratelimiter.NewRateLimiter(5, time.Second, 5*time.Minute)

	// Teste de limitação por IP
	ip := "192.168.1.1"
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ip), "A requisição deve ser permitida")
	}
	// A sexta requisição deve ser bloqueada
	assert.False(t, limiter.Allow(ip), "A sexta requisição deve ser bloqueada")

	// Aguarda o tempo de expiração
	time.Sleep(5 * time.Minute)

	// Após o tempo de expiração, as requisições devem ser permitidas novamente
	assert.True(t, limiter.Allow(ip), "As requisições devem ser permitidas após o tempo de expiração")
}

func TestRateLimiter_LimitByToken(t *testing.T) {
	// Configuração do rate limiter com limite de 10 requisições por segundo por token
	limiter := ratelimiter.NewRateLimiter(10, time.Second, 5*time.Minute)

	// Teste de limitação por token
	token := "abc123"
	for i := 0; i < 10; i++ {
		assert.True(t, limiter.Allow(token), "A requisição deve ser permitida")
	}
	// A décima primeira requisição deve ser bloqueada
	assert.False(t, limiter.Allow(token), "A décima primeira requisição deve ser bloqueada")

	// Aguarda o tempo de expiração
	time.Sleep(5 * time.Minute)

	// Após o tempo de expiração, as requisições devem ser permitidas novamente
	assert.True(t, limiter.Allow(token), "As requisições devem ser permitidas após o tempo de expiração")
}
