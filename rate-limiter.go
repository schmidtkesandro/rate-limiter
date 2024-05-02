package main

import (
	"context"
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
	"github.com/go-redis/redis/v8"
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
	RedisClient    *redis.Client // Cliente Redis
}

// getIP retorna o endereço IP do cliente
func getIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ", ")
		return ips[0]
	}
	return r.RemoteAddr
}

// IPRateLimiter retorna o rate limiter associado ao IP
func (limiter *RateLimiter) IPRateLimit(ip string) (*rate.Limiter, bool) {
	config, ok := limiter.TokenConfigs["Default"]
	if !ok {
		// Se não houver uma configuração para o token, retorna false
		return nil, false
	}
	lim, ok := limiter.IPRateLimiters[ip]
	if !ok {
		fmt.Println("Passei aqui ip 1 com ok = ", ok, config.MaxRequests)
		fmt.Println("limiter.Config.MaxRequests", limiter.Config.MaxRequests)
		lim = rate.NewLimiter(rate.Limit(1), config.MaxRequests)
		limiter.IPRateLimiters[ip] = lim
	}
	remainingTokens := lim.Burst()
	fmt.Printf("Remaining IP: %d\n", remainingTokens)
	return lim, true
}

type TokenLimit struct {
	Limiter          *rate.Limiter
	TokenBlockPeriod time.Duration
}

// TokenRateLimit retorna o rate limiter para o token especificado
func (limiter *RateLimiter) TokenRateLimit(token string) (*rate.Limiter, bool) {
	// Verifica se há um rate limiter para este token
	config, ok := limiter.TokenConfigs[token]
	if !ok {
		config, ok = limiter.TokenConfigs["Padrao"]
		if !ok {
			config, ok = limiter.TokenConfigs["Default"]
			if !ok {
				// Se não houver uma configuração para o token, retorna false
				return nil, false
			}
		}
	}
	// Obtém o rate limiter para este token
	lim, ok := limiter.TokenLimits[token]
	if !ok {
		// Se não houver um rate limiter para este token, cria um novo
		fmt.Println("Passei aqui ", token, " com ok = ", ok, config.MaxRequests)
		fmt.Println("limiter.Config.MaxRequests", limiter.Config.MaxRequests)
		lim = rate.NewLimiter(rate.Limit(1), config.MaxRequests)
		// Execute some actions
		// for i := 0; i < 5; i++ {
		// 	if lim.Allow() {
		// 		fmt.Printf("Action %d allowed\n", i+1)
		// 	} else {
		// 		fmt.Printf("Action %d blocked\n", i+1)

		// 	}
		// 	remainingTokens := lim.Burst()
		// 	fmt.Printf("Remaining tokens: %d\n", remainingTokens)
		// }
		limiter.TokenLimits[token] = lim
		// Define o TokenBlockPeriod para o rate limiter

	}
	remainingTokens := lim.Burst()
	fmt.Printf("Remaining tokens: %d\n", remainingTokens)
	return lim, true
}

// isIPBlocked verifica se o IP está na lista de bloqueio
func (limiter *RateLimiter) isIPBlocked(ip string) bool {
	// Verifica se o token está na lista de tokens bloqueados no Redis
	blockTimeStr, err := limiter.RedisClient.Get(context.Background(), "blocked:"+ip).Result()
	if err != nil && err != redis.Nil {
		log.Printf("Error getting block time for ip %s: %v", ip, err)
		return false
	}
	if blockTimeStr != "" {
		// Converte o tempo de bloqueio de timestamp em segundos para time.Time
		blockTimeUnix, err := strconv.ParseInt(blockTimeStr, 10, 64)
		if err != nil {
			log.Printf("Error parsing block time for ip %s: %v", ip, err)
			return false
		}
		blockTime := time.Unix(blockTimeUnix, 0)

		// Verifica se o período de bloqueio já expirou
		if time.Since(blockTime) < limiter.Config.IPBlockPeriod {
			return true
		}
		// Remove o token da lista de tokens bloqueados no Redis
		_, err = limiter.RedisClient.Del(context.Background(), "blocked:"+ip).Result()
		if err != nil {
			log.Printf("Error removing ip %s from block list: %v", ip, err)
		}
	}
	return false
}

// blockIP bloqueia o IP na lista de bloqueio
func (limiter *RateLimiter) blockIP(ip string) {

	ctx := context.Background()
	// Obter o tempo de bloqueio do token a partir das configurações
	blockPeriod := limiter.TokenConfigs["Default"].IPBlockPeriod
	fmt.Println("blockPeriod: ", blockPeriod)
	// Definir o tempo de desbloqueio do token
	unblockTime := time.Now().Add(blockPeriod)
	fmt.Println("unblockTime: ", unblockTime)
	// Armazenar o tempo de desbloqueio na lista de tokens bloqueados no Redis
	key := "blocked:" + ip
	fmt.Println("key: ", key)
	if err := limiter.RedisClient.Set(ctx, key, unblockTime.Unix(), blockPeriod).Err(); err != nil {
		log.Printf("Error blocking ip %s: %v", ip, err)
	}
	// Definir o tempo de expiração para a chave
	if err := limiter.RedisClient.Expire(ctx, key, blockPeriod).Err(); err != nil {
		log.Printf("Error setting expiration for ip %s: %v", ip, err)
	}
}

// blockToken bloqueia o token na lista de bloqueio
func (limiter *RateLimiter) blockToken(token string) {
	ctx := context.Background()
	// Obter o tempo de bloqueio do token a partir das configurações
	blockPeriod := limiter.TokenConfigs[token].TokenBlockPeriod
	config, ok := limiter.TokenConfigs[token]
	if !ok {
		config, ok = limiter.TokenConfigs["Padrao"]
		if ok {
			blockPeriod = config.TokenBlockPeriod
		} else {
			config, ok := limiter.TokenConfigs["Default"]
			blockPeriod = config.TokenBlockPeriod
			if !ok {
				log.Printf("Error block token")
			}

		}
	}
	fmt.Println("blockPeriod: ", blockPeriod)
	// Definir o tempo de desbloqueio do token
	unblockTime := time.Now().Add(blockPeriod)
	fmt.Println("unblockTime: ", unblockTime)
	// Armazenar o tempo de desbloqueio na lista de tokens bloqueados no Redis
	key := "blocked:" + token
	fmt.Println("key: ", key)
	if err := limiter.RedisClient.Set(ctx, key, unblockTime.Unix(), blockPeriod).Err(); err != nil {
		log.Printf("Error blocking token %s: %v", token, err)
	}
	// Definir o tempo de expiração para a chave
	if err := limiter.RedisClient.Expire(ctx, key, blockPeriod).Err(); err != nil {
		log.Printf("Error setting expiration for token %s: %v", token, err)
	}
}

// isTokenBlocked verifica se o token está na lista de bloqueio
func (limiter *RateLimiter) isTokenBlocked(token string) bool {
	// Verifica se o token está na lista de tokens bloqueados no Redis
	blockTimeStr, err := limiter.RedisClient.Get(context.Background(), "blocked:"+token).Result()
	if err != nil && err != redis.Nil {
		log.Printf("Error getting block time for token %s: %v", token, err)
		return false
	}
	if blockTimeStr != "" {
		// Converte o tempo de bloqueio de timestamp em segundos para time.Time
		blockTimeUnix, err := strconv.ParseInt(blockTimeStr, 10, 64)
		if err != nil {
			log.Printf("Error parsing block time for token %s: %v", token, err)
			return false
		}
		blockTime := time.Unix(blockTimeUnix, 0)

		// Verifica se o período de bloqueio já expirou
		if time.Since(blockTime) < limiter.Config.TokenBlockPeriod {
			return true
		}
		// Remove o token da lista de tokens bloqueados no Redis
		_, err = limiter.RedisClient.Del(context.Background(), "blocked:"+token).Result()
		if err != nil {
			log.Printf("Error removing token %s from block list: %v", token, err)
		}
	}
	return false
}

// LoadTokenConfigs lê as informações do arquivo .env e retorna um mapa indexado pelo NAME_TOKEN
func LoadTokenConfigs(cfg Config, numeroMaximodeTokens int) map[string]TokenConfig {
	fmt.Println("LoadTokenConfigs")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	// Variáveis para armazenar as configurações dos tokens
	tokenConfigs := make(map[string]TokenConfig)
	// Loop para percorrer as variáveis de ambiente até no máximo 10 vezes
	for i := 0; i < numeroMaximodeTokens; i++ {
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
	// Armazenar as configurações Default no mapa para os tokens que não possuem configuração específica
	defaultTokenConfig := TokenConfig{
		MaxRequests:      cfg.MaxRequests,
		IPBlockPeriod:    cfg.IPBlockPeriod,
		TokenBlockPeriod: cfg.IPBlockPeriod,
	}
	// Armazenar as configurações Default no mapa para os tokens que não possuem configuração específica
	tokenConfigs["Default"] = defaultTokenConfig
	//mostra as configurações do arquivo .env
	for tokenName, config := range tokenConfigs {
		log.Printf("Token: %s, Max Requests: %d, IP Block Period: %s, Token Block Period: %s",
			tokenName, config.MaxRequests, config.IPBlockPeriod.String(), config.TokenBlockPeriod.String())
	}
	return tokenConfigs
}

// CheckRateLimit verifica se uma solicitação excede o limite de taxa
func (limiter *RateLimiter) CheckRateLimit(ip, token string) error {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if token == "" {
		if limiter.isIPBlocked(ip) {
			// Retorna um erro se o IP estiver bloqueado
			return fmt.Errorf("IP blocked")
		}
		lim, ok := limiter.IPRateLimit(ip)
		if !ok {
			// Retorna um erro se o token não for válido
			return fmt.Errorf("invalid ip")
		}
		// if limiter.isIPBlocked(ip) {
		// 	// Retorna um erro se o token estiver bloqueado
		// 	return fmt.Errorf("ip blocked")
		// }

		if !lim.Allow() {
			// Bloqueia o ip e retorna um erro se a solicitação exceder o limite
			limiter.blockIP(ip)
			return fmt.Errorf("ip - too many requests")
		}
	} else {
		lim, ok := limiter.TokenRateLimit(token)
		if !ok {
			// Retorna um erro se o token não for válido
			return fmt.Errorf("invalid token")
		}

		if limiter.isTokenBlocked(token) {
			// Retorna um erro se o token estiver bloqueado
			return fmt.Errorf("token blocked")
		}
		remainingTokens := lim.Burst()
		fmt.Printf("Remaining tokens antes Allow: %d\n", remainingTokens)
		if !lim.Allow() {
			// Bloqueia o token e retorna um erro se a solicitação exceder o limite
			remainingTokens := lim.Burst()
			fmt.Printf("Remaining tokens depois Allow: %d\n", remainingTokens)
			limiter.blockToken(token)
			return fmt.Errorf("token - too many requests")
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

func main() {
	// Inicializa o cliente Redis
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // Endereço padrão do servidor Redis
	})
	defer client.Close() // Fechar o cliente Redis quando não estiver mais em uso

	// Verifica a conexão com o servidor Redis
	ctx := context.Background()
	pong, err := client.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Error connecting to Redis: %v", err)
	}
	log.Printf("Connected to Redis: %s", pong)

	//Configuração padrão
	cfg := Config{
		MaxRequests:      4,               // Número máximo de requisições permitidas por segundo
		IPBlockPeriod:    2 * time.Minute, // Período de bloqueio para IPs
		TokenBlockPeriod: 3 * time.Minute, // Período de bloqueio para tokens
	}
	// configura o número de tokens que podem ser personalizados com variável de ambiente
	numeroMaximodeTokens := 10
	// Carrega as configurações dos tokens do arquivo .env
	tokenConfigs := LoadTokenConfigs(cfg, numeroMaximodeTokens)

	// Inicializa o rate limiter com o cliente Redis
	limiter := &RateLimiter{
		Config:         cfg,
		IPRateLimiters: make(map[string]*rate.Limiter),
		TokenLimits:    make(map[string]*rate.Limiter),
		BlockedIPs:     make(map[string]time.Time),
		BlockedTokens:  make(map[string]time.Time),
		TokenConfigs:   tokenConfigs,
		RedisClient:    client,
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
