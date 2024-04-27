package ratelimiter

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu           sync.Mutex
	limits       map[string]*limitInfo
	defaultLimit int
	window       time.Duration
	expiry       time.Duration
}

type limitInfo struct {
	count      int
	lastAccess time.Time
}

func NewRateLimiter(defaultLimit int, window, expiry time.Duration) *RateLimiter {
	return &RateLimiter{
		limits:       make(map[string]*limitInfo),
		defaultLimit: defaultLimit,
		window:       window,
		expiry:       expiry,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Verifica se a chave já existe no mapa
	info, exists := rl.limits[key]
	if !exists {
		info = &limitInfo{}
		rl.limits[key] = info
	}

	// Verifica se o tempo de expiração para a chave passou
	if time.Since(info.lastAccess) > rl.expiry {
		info.count = 0
	}

	// Verifica se o limite de requisições foi atingido
	if info.count >= rl.defaultLimit {
		return false
	}

	// Atualiza as informações e permite a requisição
	info.count++
	info.lastAccess = time.Now()

	return true
}
