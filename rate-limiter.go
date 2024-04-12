package main

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Config é uma estrutura para armazenar configurações do rate limiter
type Config struct {
	MaxRequests      int           // Número máximo de requisições permitidas por segundo
	IPBlockPeriod    time.Duration // Tempo de bloqueio do IP em caso de excesso de requisições
	TokenBlockPeriod time.Duration // Tempo de bloqueio do Token em caso de excesso de requisições
}

// RateLimiter é uma estrutura que armazena os rate limiters
type RateLimiter struct {
	IPRateLimiter    *rate.Limiter
	TokenRateLimiter map[string]*rate.Limiter // Mapa de tokens para limiters
	IPBlockList      map[string]time.Time     // Lista de IPs bloqueados
	TokenBlockList   map[string]time.Time     // Lista de Tokens bloqueados
	Config           Config
}

// NewRateLimiter cria um novo rate limiter com base nas configurações fornecidas
func NewRateLimiter(cfg Config) *RateLimiter {
	return &RateLimiter{
		IPRateLimiter:    rate.NewLimiter(rate.Limit(cfg.MaxRequests), 1),
		TokenRateLimiter: make(map[string]*rate.Limiter),
		IPBlockList:      make(map[string]time.Time),
		TokenBlockList:   make(map[string]time.Time),
		Config:           cfg,
	}
}

// Middleware é um middleware Gin que executa o rate limiter
func (limiter *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Verifica se o IP está na lista de bloqueio
		if blockTime, ok := limiter.IPBlockList[c.ClientIP()]; ok {
			if time.Since(blockTime) < limiter.Config.IPBlockPeriod {
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "you have reached the maximum number of requests allowed from this IP",
				})
				c.Abort()
				return
			}
			delete(limiter.IPBlockList, c.ClientIP())
		}

		// Verifica o token de acesso no header
		token := c.GetHeader("API_KEY")
		if token != "" {
			// Verifica se o token está na lista de bloqueio
			if blockTime, ok := limiter.TokenBlockList[token]; ok {
				if time.Since(blockTime) < limiter.Config.TokenBlockPeriod {
					c.JSON(http.StatusTooManyRequests, gin.H{
						"error": "you have reached the maximum number of requests allowed with this token",
					})
					c.Abort()
					return
				}
				delete(limiter.TokenBlockList, token)
			}

			// Verifica se há um rate limiter para este token
			lim, ok := limiter.TokenRateLimiter[token]
			if !ok {
				// Se não houver, cria um novo e adiciona ao mapa
				lim = rate.NewLimiter(rate.Limit(limiter.Config.MaxRequests), 1)
				limiter.TokenRateLimiter[token] = lim
			}

			// Tenta pegar uma permissão do rate limiter
			if !lim.Allow() {
				// Bloqueia o token e retorna um erro
				limiter.TokenBlockList[token] = time.Now()
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "you have reached the maximum number of requests allowed with this token",
				})
				c.Abort()
				return
			}
		} else {
			// Se não houver token, usa o rate limiter baseado no IP
			if !limiter.IPRateLimiter.Allow() {
				// Bloqueia o IP e retorna um erro
				limiter.IPBlockList[c.ClientIP()] = time.Now()
				c.JSON(http.StatusTooManyRequests, gin.H{
					"error": "you have reached the maximum number of requests allowed from this IP",
				})
				c.Abort()
				return
			}
		}

		// Continua o fluxo normal se todas as verificações passaram
		c.Next()
	}
}

func main() {
	// Configurações do rate limiter
	cfg := Config{
		MaxRequests:      10,              // Máximo de 10 requisições por segundo
		IPBlockPeriod:    5 * time.Minute, // IP bloqueado por 5 minutos após exceder o limite
		TokenBlockPeriod: 5 * time.Minute, // Token bloqueado por 5 minutos após exceder o limite
	}

	// Cria um novo rate limiter
	limiter := NewRateLimiter(cfg)

	// Configuração do servidor Gin
	router := gin.Default()

	// Aplica o middleware do rate limiter
	router.Use(limiter.Middleware())

	// Rota de teste
	router.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "Hello World!")
	})

	// Inicia o servidor na porta 8080
	router.Run(":8080")
}
