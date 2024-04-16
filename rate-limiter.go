package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

// Config contém as configurações do Rate Limiter
type Config struct {
	MaxRequests      int           // Número máximo de requisições permitidas por segundo
	IPBlockPeriod    time.Duration // Período de bloqueio para IPs
	TokenBlockPeriod time.Duration // Período de bloqueio para tokens
}

// RateLimiter implementa um Rate Limiter para o Chi
type RateLimiter struct {
	Config          Config                    // Configuração do Rate Limiter
	IPRateLimiters  map[string]*rate.Limiter  // Rate limiters por IP
	TokenRateLimits map[string]TokenRateLimit // Rate limits por token
	IPBlockList     map[string]time.Time      // Lista de IPs bloqueados
	TokenBlockList  map[string]time.Time      // Lista de tokens bloqueados
	TokenConfigs    map[string]Config         // Configuração específica por token
	mu              sync.Mutex                // Mutex para sincronização de acesso
}

// TokenRateLimit armazena a configuração do limite e o rate limiter associado a um token
type TokenRateLimit struct {
	Config  *Config       // Configuração do limite
	Limiter *rate.Limiter // Rate limiter
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
			tokenRateLimit, ok := limiter.TokenRateLimits[token]
			if !ok {
				// Se não houver, usa a configuração padrão ou configuração específica do token
				config := limiter.Config // Configuração padrão
				if cfg, exists := limiter.TokenConfigs[token]; exists {
					config = cfg // Configuração específica do token
				}
				tokenRateLimit = TokenRateLimit{
					Config:  &config,
					Limiter: rate.NewLimiter(rate.Limit(config.MaxRequests), 1),
				}
				limiter.TokenRateLimits[token] = tokenRateLimit
			}

			if !tokenRateLimit.Limiter.Allow() {
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

			// Tenta pegar uma permissão do rate limiter do IP
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
	// Carrega variáveis de ambiente de um arquivo .env, se existir
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found, using default configurations")
	}

	// Configurações padrão
	defaultConfig := Config{
		MaxRequests:      getEnvInt("MAX_REQUESTS", 10),                       // Número máximo de requisições permitidas por segundo
		IPBlockPeriod:    getEnvDuration("IP_BLOCK_PERIOD", 1*time.Minute),    // Período de bloqueio para IPs
		TokenBlockPeriod: getEnvDuration("TOKEN_BLOCK_PERIOD", 1*time.Minute), // Período de bloqueio para tokens
	}

	// Inicializa o Rate Limiter
	limiter := &RateLimiter{
		Config:          defaultConfig,
		IPRateLimiters:  make(map[string]*rate.Limiter),
		TokenRateLimits: make(map[string]TokenRateLimit),
		IPBlockList:     make(map[string]time.Time),
		TokenBlockList:  make(map[string]time.Time),
		TokenConfigs:    make(map[string]Config),
	}

	// Configurações específicas por token
	// Aqui você pode definir configurações específicas para cada token, se necessário
	// Exemplo: limiter.TokenConfigs["token1"] = Config{MaxRequests: 50, IPBlockPeriod: 1*time.Minute, TokenBlockPeriod: 1*time.Minute}

	// Configura o roteador Chi
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(limiter.Middleware)

	// Rota de exemplo
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})

	// Servidor HTTP na porta 8080
	log.Println("Server started on port 8080")
	http.ListenAndServe(":8080", r)
}

// getEnvInt retorna o valor da variável de ambiente como um inteiro, ou o valor padrão se não estiver definido ou for inválido
func getEnvInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	fmt.Println("Value:", value)
	if err != nil {
		log.Printf("Invalid value for %s, using default value %d\n", key, defaultValue)
		return defaultValue
	}
	return value
}

// getEnvDuration retorna o valor da variável de ambiente como uma duração, ou o valor padrão se não estiver definido ou for inválido
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		log.Printf("Invalid value for %s, using default value %s\n", key, defaultValue)
		return defaultValue
	}
	return value

}
