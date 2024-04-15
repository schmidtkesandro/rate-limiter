package main

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"golang.org/x/time/rate"
)

// Config armazena as configurações do Rate Limiter
type Config struct {
	MaxRequests      int           // Número máximo de requisições permitidas
	IPBlockPeriod    time.Duration // Período de bloqueio por IP quando o limite é excedido
	TokenBlockPeriod time.Duration // Período de bloqueio por Token quando o limite é excedido
}

// DefaultConfig armazena as configurações padrão do Rate Limiter
var DefaultConfig = Config{
	MaxRequests:      100,
	IPBlockPeriod:    5 * time.Minute,
	TokenBlockPeriod: 5 * time.Minute,
}

// RateLimiter implementa o controle de taxa para IP e Token
type RateLimiter struct {
	IPRateLimiters  map[string]*rate.Limiter // Mapa de rate limiters por IP
	TokenRateLimits map[string]Config        // Mapa de configurações de limite por token
	TokenBlockList  map[string]time.Time     // Lista de Tokens bloqueados
	IPBlockList     map[string]time.Time     // Lista de IPs bloqueados
	Config          Config                   // Configuração do Rate Limiter
	mu              sync.RWMutex             // Mutex para operações seguras em mapas concorrentes
}

// NewRateLimiter cria uma nova instância de RateLimiter
func NewRateLimiter(cfg Config) *RateLimiter {
	return &RateLimiter{
		IPRateLimiters:  make(map[string]*rate.Limiter),
		TokenRateLimits: make(map[string]Config),
		TokenBlockList:  make(map[string]time.Time),
		IPBlockList:     make(map[string]time.Time),
		Config:          cfg, // Adicionando a configuração ao RateLimiter
	}
}

// SetTokenRateLimit define o limite de taxa para um token específico
func (limiter *RateLimiter) SetTokenRateLimit(token string, cfg Config) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.TokenRateLimits[token] = cfg
}

// Middleware implementa o middleware do Rate Limiter para o Chi
func (limiter *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Obtém apenas o endereço IP do cliente sem a porta
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "failed to parse client IP address", http.StatusInternalServerError)
			return
		}

		limiter.mu.Lock()
		defer limiter.mu.Unlock()

		// Verifica se o IP está na lista de bloqueio
		if blockTime, ok := limiter.IPBlockList[ip]; ok {
			if time.Since(blockTime) < limiter.Config.IPBlockPeriod {
				http.Error(w, "you have reached the maximum number of requests allowed from this IP", http.StatusTooManyRequests)
				return
			}
			delete(limiter.IPBlockList, ip)
		}

		// Verifica o token de acesso no header
		token := r.Header.Get("API_KEY")
		fmt.Println("token:", token)
		if token != "" {
			// Verifica se o token está na lista de bloqueio
			if blockTime, ok := limiter.TokenBlockList[token]; ok {
				if time.Since(blockTime) < limiter.Config.TokenBlockPeriod {
					http.Error(w, "you have reached the maximum number of requests allowed with this token", http.StatusTooManyRequests)
					return
				}
				delete(limiter.TokenBlockList, token)
			}

			// Verifica se há um rate limiter para este token
			_, ok := limiter.TokenRateLimits[token]
			if !ok {
				// Se não houver, cria um novo e adiciona ao mapa
				cfg, ok := limiter.TokenRateLimits[token]
				if !ok {
					cfg = limiter.Config // Se não houver configuração específica do token, use a configuração padrão
				}
				limiter.TokenRateLimits[token] = cfg
			}

			// Tenta pegar uma permissão do rate limiter
			if _, ok := limiter.IPRateLimiters[ip]; !ok {
				limiter.IPRateLimiters[ip] = rate.NewLimiter(rate.Limit(limiter.Config.MaxRequests), 1)
			}

			if !limiter.IPRateLimiters[ip].Allow() {
				// Bloqueia o token e retorna um erro
				limiter.TokenBlockList[token] = time.Now()
				http.Error(w, "you have reached the maximum number of requests allowed with this token", http.StatusTooManyRequests)
				return
			}
		} else {
			// Se não houver token, usa o rate limiter baseado no IP
			// Verifica se há um rate limiter para este IP
			if _, ok := limiter.IPRateLimiters[ip]; !ok {
				limiter.IPRateLimiters[ip] = rate.NewLimiter(rate.Limit(limiter.Config.MaxRequests), 1)
			}

			// Tenta pegar uma permissão do rate limiter
			if !limiter.IPRateLimiters[ip].Allow() {
				// Bloqueia o IP e retorna um erro
				limiter.IPBlockList[ip] = time.Now()
				http.Error(w, "you have reached the maximum number of requests allowed from this IP", http.StatusTooManyRequests)
				return
			}
		}

		// Continua o fluxo normal se todas as verificações passaram
		next.ServeHTTP(w, r)
	})
}

func main() {
	// Defina as configurações do rate limiter
	cfg := Config{
		MaxRequests:      2,
		IPBlockPeriod:    1 * time.Minute,
		TokenBlockPeriod: 1 * time.Minute,
	}

	// Crie uma nova instância de RateLimiter com as configurações definidas
	limiter := NewRateLimiter(cfg)

	// Adicione os limites de taxa para diferentes tokens
	limiter.SetTokenRateLimit(" token1", Config{
		MaxRequests:      5,
		IPBlockPeriod:    1 * time.Minute,
		TokenBlockPeriod: 1 * time.Minute,
	})
	limiter.SetTokenRateLimit(" token2", Config{
		MaxRequests:      7,
		IPBlockPeriod:    1 * time.Minute,
		TokenBlockPeriod: 1 * time.Minute,
	})

	// Inicialize o roteador Chi
	r := chi.NewRouter()

	// Use o middleware do Rate Limiter
	r.Use(middleware.Logger)
	r.Use(limiter.Middleware)

	// Defina a rota
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello World!"))
	})

	// Inicie o servidor na porta 8080
	fmt.Println("Server is running on :8080")
	http.ListenAndServe(":8080", r)
}
