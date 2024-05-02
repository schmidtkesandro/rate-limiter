package testratelimiter_test

import (
	"testing"
	"time"

	ratelimiter "github.com/schmidtkesandro/rate-limiter/testratelimiter"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_LimitByIP(t *testing.T) {
	// Configuração do rate limiter com limite de 5 requisições por segundo por IP
	limiter := ratelimiter.NewRateLimiter(5, time.Second, 1*time.Minute)

	// Teste de limitação por IP
	ip := "192.168.1.1"
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ip), "A requisição deve ser permitida")
	}
	// A sexta requisição deve ser bloqueada
	assert.False(t, limiter.Allow(ip), "A sexta requisição deve ser bloqueada")

	// Aguarda o tempo de expiração
	time.Sleep(1 * time.Minute)

	// Após o tempo de expiração, as requisições devem ser permitidas novamente
	assert.True(t, limiter.Allow(ip), "As requisições devem ser permitidas após o tempo de expiração")
}

func TestRateLimiter_LimitByToken(t *testing.T) {
	// Configuração do rate limiter com limite de 10 requisições por segundo por token
	limiter := ratelimiter.NewRateLimiter(10, time.Second, 1*time.Minute)

	// Teste de limitação por token
	token := "abc123"
	for i := 0; i < 10; i++ {
		assert.True(t, limiter.Allow(token), "A requisição deve ser permitida")
	}
	// A décima primeira requisição deve ser bloqueada
	assert.False(t, limiter.Allow(token), "A décima primeira requisição deve ser bloqueada")

	// Aguarda o tempo de expiração
	time.Sleep(1 * time.Minute)

	// Após o tempo de expiração, as requisições devem ser permitidas novamente
	assert.True(t, limiter.Allow(token), "As requisições devem ser permitidas após o tempo de expiração")
}
func TestRateLimiter_LimitByTokenandIPblocked(t *testing.T) {
	// Configuração do rate limiter com limite de 10 requisições por segundo por token
	limiter := ratelimiter.NewRateLimiter(5, 1*time.Minute, 1*time.Minute)
	ip := "192.168.1.2"
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(ip), "A requisição deve ser permitida")
	}
	// A sexta requisição deve ser bloqueada
	assert.False(t, limiter.Allow(ip), "A sexta requisição deve ser bloqueada")
	// Teste de limitação por token

	token := "abc123"
	for i := 0; i < 5; i++ {
		assert.True(t, limiter.Allow(token), "A requisição deve ser permitida")
	}
	// A décima primeira requisição deve ser bloqueada
	assert.False(t, limiter.Allow(token), "A sexta requisição deve ser bloqueada")

	// Aguarda o tempo de expiração
	time.Sleep(1 * time.Minute)

	// Após o tempo de expiração, as requisições devem ser permitidas novamente
	assert.True(t, limiter.Allow(token), "A requisição deve ser permitida após o tempo de expiração do Token")
	assert.True(t, limiter.Allow(ip), "A requisição deve ser permitida após expiração do IP")
}
