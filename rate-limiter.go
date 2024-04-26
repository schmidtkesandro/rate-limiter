package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
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

// TokenConfig contém as configurações para um token
type TokenConfig struct {
	MaxRequests      int
	IPBlockPeriod    time.Duration
	TokenBlockPeriod time.Duration
}

// RateLimiter implementa um Rate Limiter para o Chi
type RateLimiter struct {
	Config         Config                   // Configuração padrão do Rate Limiter
	IPRateLimiters map[string]*rate.Limiter // Rate limiters por IP
	TokenLimits    map[string]*rate.Limiter // Configurações de token
	mu             sync.Mutex               // Mutex para sincronização de acesso
	BlockedIPs     map[string]time.Time     // IPs bloqueados e o momento em que foram bloqueados
	BlockedTokens  map[string]time.Time     // Tokens bloqueados e o momento em que foram bloqueados
	TokenConfigs   map[string]TokenConfig
}

// Values retorna os valores da configuração de um token específico.
// Se o token não existir nas configurações, retorna false.
// func (config *rate.Limiter) Values() (int, time.Duration, time.Duration, bool) {
// 	if config == (TokenConfig{}) {
// 		return 0, 0, 0, false
// 	}
// 	return config.MaxRequests, config.IPBlockPeriod, config.TokenBlockPeriod, true
// }

// getIP retorna o endereço IP do cliente
func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ", ")
		return ips[0]
	}
	return r.RemoteAddr
}

// CheckRateLimit verifica se uma solicitação excede o limite de taxa
func (limiter *RateLimiter) CheckRateLimit(ip, token string) error {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if token != "" {
		lim, ok := limiter.TokenRateLimit(token)
		if !ok {
			lim, ok = limiter.TokenRateLimit("Padrao")
			if !ok {
				// Caso não encontre o token utiliza o valor Default
				lim, ok = limiter.TokenRateLimit("Default")
				if !ok {
					// Retorna um erro se o token não for válido
					return fmt.Errorf("invalid token")
				}
			}
		}
		if limiter.isTokenBlocked(token) {
			// Retorna um erro se o token estiver bloqueado
			return fmt.Errorf("token blocked")
		}

		if !lim.Allow() {
			// Bloqueia o token e retorna um erro se a solicitação exceder o limite
			limiter.blockToken(token)
			return fmt.Errorf("too many requests")
		}
	} else {
		if limiter.isIPBlocked(ip) {
			// Retorna um erro se o IP estiver bloqueado
			return fmt.Errorf("IP blocked")
		}

		if !limiter.IPRateLimiter(ip).Allow() {
			// Bloqueia o IP e retorna um erro se a solicitação exceder o limite
			limiter.blockIP(ip)
			return fmt.Errorf("too many requests")
		}
	}

	return nil
}

// Middleware implementa o middleware do Rate Limiter para o Chi
func (limiter *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Obtém apenas o endereço IP do cliente sem a porta
		ip := getIP(r)
		// Verifica o token de acesso no header
		token := r.Header.Get("API_KEY")
		// Verifica se a solicitação excede o limite de taxa
		if err := limiter.CheckRateLimit(ip, token); err != nil {
			http.Error(w, err.Error(), http.StatusTooManyRequests)
			return
		}
		// Continua o fluxo normal se todas as verificações passaram
		next.ServeHTTP(w, r)
	})
}

// IPRateLimiter retorna o rate limiter associado ao IP
func (limiter *RateLimiter) IPRateLimiter(ip string) *rate.Limiter {
	lim, ok := limiter.IPRateLimiters[ip]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(limiter.Config.MaxRequests), 1)
		limiter.IPRateLimiters[ip] = lim
	}
	return lim
}

// TokenRateLimit retorna o rate limiter para o token especificado
func (limiter *RateLimiter) TokenRateLimit(token string) (*rate.Limiter, bool) {
	// Verifica se há um rate limiter para este token
	config, ok := limiter.TokenConfigs[token]
	if !ok {
		// Se não houver uma configuração para o token, retorna false
		return nil, false
	}
	// Obtém o rate limiter para este token
	lim, ok := limiter.TokenLimits[token]
	if !ok {
		// Se não houver um rate limiter para este token, cria um novo
		lim = rate.NewLimiter(rate.Limit(config.MaxRequests), 1)
		limiter.TokenLimits[token] = lim
	}
	return lim, true
}

// isIPBlocked verifica se o IP está na lista de bloqueio
func (limiter *RateLimiter) isIPBlocked(ip string) bool {
	// Verifica se o IP está na lista de IPs bloqueados
	if blockTime, ok := limiter.BlockedIPs[ip]; ok {
		// Verifica se o período de bloqueio já expirou
		fmt.Println("limite IP: ", limiter.Config.IPBlockPeriod)
		if time.Since(blockTime) < limiter.Config.IPBlockPeriod {
			return true
		}
		// Remove o IP da lista de IPs bloqueados
		delete(limiter.BlockedIPs, ip)
	}
	return false
}

// blockIP bloqueia o IP na lista de bloqueio
func (limiter *RateLimiter) blockIP(ip string) {
	limiter.BlockedIPs[ip] = time.Now()
}
func (limiter *RateLimiter) blockToken(token string) {
	limiter.BlockedTokens[token] = time.Now()
}

// isTokenBlocked verifica se o token está na lista de bloqueio
func (limiter *RateLimiter) isTokenBlocked(token string) bool {
	// Verifica se o token está na lista de tokens bloqueados
	if blockTime, ok := limiter.BlockedTokens[token]; ok {
		// Verifica se o período de bloqueio já expirou
		if time.Since(blockTime) < limiter.Config.TokenBlockPeriod {
			return true
		}
		// Remove o token da lista de tokens bloqueados
		delete(limiter.BlockedTokens, token)
	}
	return false
}

// LoadTokenConfigs lê as informações do arquivo .env e retorna um mapa indexado pelo NAME_TOKEN
func LoadTokenConfigs(cfg Config) map[string]TokenConfig {
	fmt.Println("LoadTokenConfigs")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// Variáveis para armazenar as configurações dos tokens
	tokenConfigs := make(map[string]TokenConfig)
	// Loop para percorrer as variáveis de ambiente até no máximo 10 vezes
	for i := 0; i < 10; i++ {
		// Nome do token
		tokenName := os.Getenv("NAME" + strconv.Itoa(i) + "_TOKEN")
		if tokenName == "" {
			// Se não houver mais tokens, saia do loop
			break
		}
		// Configurações do token
		maxRequestsStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_MAX_REQUESTS")
		maxRequests, err := strconv.Atoi(maxRequestsStr)
		if err != nil {
			log.Printf("Error converting max requests for token %s: %v", tokenName, err)
			continue
		}
		ipBlockPeriodStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_IP_BLOCK_PERIOD")
		ipBlockPeriod, err := time.ParseDuration(ipBlockPeriodStr)
		if err != nil {
			log.Printf("Error parsing IP block period for token %s: %v", tokenName, err)
			continue
		}

		tokenBlockPeriodStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_TOKEN_BLOCK_PERIOD")
		tokenBlockPeriod, err := time.ParseDuration(tokenBlockPeriodStr)
		if err != nil {
			log.Printf("Error parsing token block period for token %s: %v", tokenName, err)
			continue
		}

		// Armazenar as configurações do token no mapa
		tokenConfigs[tokenName] = TokenConfig{
			MaxRequests:      maxRequests,
			IPBlockPeriod:    ipBlockPeriod,
			TokenBlockPeriod: tokenBlockPeriod,
		}
	}
	// // Armazenar as configurações Default no mapa para os tokens que não possuem configuração específica
	// tokenConfigs["Default"] = TokenConfig{
	// 	MaxRequests:      cfg.MaxRequests,
	// 	IPBlockPeriod:    cfg.IPBlockPeriod,
	// 	TokenBlockPeriod: cfg.TokenBlockPeriod,
	// }
	// Armazenar as configurações Default no mapa para os tokens que não possuem configuração específica
	tokenConfigs["Default"] = cfg.ToTokenConfigDefault()
	for tokenName, config := range tokenConfigs {
		log.Printf("Token: %s, Max Requests: %d, IP Block Period: %s, Token Block Period: %s",
			tokenName, config.MaxRequests, config.IPBlockPeriod.String(), config.TokenBlockPeriod.String())
	}
	return tokenConfigs
}

// ToTokenConfig converte a estrutura Config em TokenConfig
func (cfg Config) ToTokenConfigDefault() TokenConfig {
	return TokenConfig{
		MaxRequests:      cfg.MaxRequests,
		IPBlockPeriod:    cfg.IPBlockPeriod,
		TokenBlockPeriod: cfg.TokenBlockPeriod,
	}
}

func main() {

	//Configuração padrão
	cfg := Config{
		MaxRequests:      4,               // Número máximo de requisições permitidas por segundo
		IPBlockPeriod:    2 * time.Minute, // Período de bloqueio para IPs
		TokenBlockPeriod: 3 * time.Minute, // Período de bloqueio para tokens
	}
	// Carrega as configurações dos tokens do arquivo .env
	tokenConfigs := LoadTokenConfigs(cfg)

	// Inicializa o rate limiter
	limiter := &RateLimiter{
		Config:         cfg,
		IPRateLimiters: make(map[string]*rate.Limiter),
		TokenLimits:    make(map[string]*rate.Limiter),
		BlockedIPs:     make(map[string]time.Time),
		BlockedTokens:  make(map[string]time.Time),
		TokenConfigs:   tokenConfigs,
	}

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
