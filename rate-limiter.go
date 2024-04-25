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
	Config         Config                   // Configuração do Rate Limiter
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

// Middleware implementa o middleware do Rate Limiter para o Chi
func (limiter *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Obtém apenas o endereço IP do cliente sem a porta
		ip := getIP(r)

		limiter.mu.Lock()
		defer limiter.mu.Unlock()
		// Verifica o token de acesso no header
		token := r.Header.Get("API_KEY")

		if token != "" {
			// Verifica se há um rate limiter para este token
			lim, ok := limiter.TokenRateLimit(token)
			if !ok {
				lim, ok = limiter.TokenRateLimit("Padraos")
				if !ok {

					http.Error(w, "Invalid token", http.StatusUnauthorized)
					return
				}
			}

			// Verifica se o IP está bloqueado
			if limiter.isIPBlocked(ip) {
				http.Error(w, "IP blocked", http.StatusTooManyRequests)
				return
			}

			// Verifica se o token está bloqueado
			if limiter.isTokenBlocked(token) {
				http.Error(w, "Token blocked", http.StatusTooManyRequests)
				return
			}

			// Verifica se a requisição excede o limite
			if !lim.Allow() {
				limiter.blockToken(token)
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}

		} else {
			// Verifica se o IP está na lista de bloqueio
			if limiter.isIPBlocked(ip) {
				http.Error(w, "Este IP está bloqueado - muitas tentativas por segundo", http.StatusTooManyRequests)
				return
			}
			// Se não houver token, usa o rate limiter baseado no IP
			// Tenta pegar uma permissão do rate limiter do IP
			if !limiter.IPRateLimiter(ip).Allow() {
				// Bloqueia o IP e retorna um erro
				limiter.blockIP(ip)
				http.Error(w, "you have reached the maximum number of requests allowed from this IP", http.StatusTooManyRequests)
				return
			}
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

// func (limiter *RateLimiter) getTokenConfig(token string) TokenConfig {
// 	maxRequests, ipBlockPeriod, tokenBlockPeriod, found := limiter.TokenLimits[token].Values()
// 	if !found {
// 		maxRequests, ipBlockPeriod, tokenBlockPeriod, found = limiter.TokenLimits["padrao"].Values()
// 		if !found {
// 			// Tratmar o caso em que não existem valores para o token
// 			maxRequests = 1
// 			ipBlockPeriod = 2
// 			tokenBlockPeriod = 2
// 		}

// 	}
// 	return TokenConfig{maxRequests, ipBlockPeriod, tokenBlockPeriod}
// }

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

// blockToken bloqueia o token na lista de bloqueio
// func (limiter *RateLimiter) blockToken(token string) {
// 	limiter.BlockedTokens[token] = time.Now()
// }

// LoadTokenConfigs lê as informações do arquivo .env e retorna um mapa indexado pelo NAME_TOKEN
func LoadTokenConfigs() map[string]TokenConfig {
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
		// fmt.Println("inicio token", "NAME"+strconv.Itoa(i)+"_TOKEN")
		if tokenName == "" {
			// Se não houver mais tokens, saia do loop
			break
		}
		// fmt.Println("token", tokenName)
		// Configurações do token
		maxRequestsStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_MAX_REQUESTS")
		// fmt.Println("Max requests: ", maxRequestsStr)
		maxRequests, err := strconv.Atoi(maxRequestsStr)
		if err != nil {
			log.Printf("Error converting max requests for token %s: %v", tokenName, err)
			continue
		}

		ipBlockPeriodStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_IP_BLOCK_PERIOD")
		// fmt.Println("ipBlockPeriodStr: ", ipBlockPeriodStr)
		ipBlockPeriod, err := time.ParseDuration(ipBlockPeriodStr)
		if err != nil {
			log.Printf("Error parsing IP block period for token %s: %v", tokenName, err)
			continue
		}

		tokenBlockPeriodStr := os.Getenv("TOKEN" + strconv.Itoa(i) + "_TOKEN_BLOCK_PERIOD")
		// fmt.Println("tokenBlockPeriodStr:", tokenBlockPeriodStr)
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
	for tokenName, config := range tokenConfigs {
		log.Printf("Token: %s, Max Requests: %d, IP Block Period: %s, Token Block Period: %s",
			tokenName, config.MaxRequests, config.IPBlockPeriod.String(), config.TokenBlockPeriod.String())
	}
	return tokenConfigs
}

func main() {
	// Carrega as configurações dos tokens do arquivo .env
	tokenConfigs := LoadTokenConfigs()

	//Configuração padrão
	cfg := Config{
		MaxRequests:      1,               // Número máximo de requisições permitidas por segundo
		IPBlockPeriod:    1 * time.Minute, // Período de bloqueio para IPs
		TokenBlockPeriod: 1 * time.Minute, // Período de bloqueio para tokens
	}

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
