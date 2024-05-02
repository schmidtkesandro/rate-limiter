Testes:
Para realizar os testes executar o comando "go test -timeout 160s" no diretório rate-limiter/testratelimiter

Redis:
Para instalar a biblioteca Redis para Go: go get github.com/go-redis/redis/v8
Para carregar o redis utilizando o docker-compose.yml execute o comando: docker-compose up -d

Configurando as variáveis de ambiente:

# Configurações padrão

NAME0_TOKEN=Padrao
TOKEN0_MAX_REQUESTS=4
TOKEN0_IP_BLOCK_PERIOD=3m
TOKEN0_TOKEN_BLOCK_PERIOD=3m

# Configurações para o token 'token1'

NAME1_TOKEN=token1
TOKEN1_MAX_REQUESTS=1
TOKEN1_IP_BLOCK_PERIOD=3m
TOKEN1_TOKEN_BLOCK_PERIOD=3m

# Configurações para o token 'token2'

NAME2_TOKEN=token2
TOKEN2_MAX_REQUESTS=2
TOKEN2_IP_BLOCK_PERIOD=1m
TOKEN2_TOKEN_BLOCK_PERIOD=1m

# Configurações para o token 'token3'

NAME3_TOKEN=token3
TOKEN3_MAX_REQUESTS=2
TOKEN3_IP_BLOCK_PERIOD=1m
TOKEN3_TOKEN_BLOCK_PERIOD=1m

para cada conjunto de variáveis de 0 a 9(para aumentar a quantidade de token alterar ), serão passadas as informações do nome do token, a quantidade máxima de requisições por segundo e o tempo de bloqueio quando ultrapassar o limite. Se não for definido um token "padrao" o programa pegará o Default definido dentro do programa:

# Configurações para o token 'Default'

  MaxRequests:      4,               // Número máximo de requisições permitidas por segundo
  IPBlockPeriod:    2 *time.Minute, // Período de bloqueio para IPs
  TokenBlockPeriod: 3* time.Minute, // Período de bloqueio para tokens

# Orientações para execução do programa

Executar o programa: no diretório rate-limiter executar a linha de comando go run rate-limiter.go
Para chamar o programa rate-limiter.go passando o token: curl -X GET <http://localhost:8080/> -H "API_KEY: token1"
Parar chamar o programa via web : localhost:8080

# Objetivo da funcionalidade

Objetivo: Desenvolver um rate limiter em Go que possa ser configurado para limitar o número máximo de requisições por segundo com base em um endereço IP específico ou em um token de acesso.

Descrição: O objetivo deste desafio é criar um rate limiter em Go que possa ser utilizado para controlar o tráfego de requisições para um serviço web. O rate limiter deve ser capaz de limitar o número de requisições com base em dois critérios:

Endereço IP: O rate limiter deve restringir o número de requisições recebidas de um único endereço IP dentro de um intervalo de tempo definido.
Token de Acesso: O rate limiter deve também poderá limitar as requisições baseadas em um token de acesso único, permitindo diferentes limites de tempo de expiração para diferentes tokens. O Token deve ser informado no header no seguinte formato:
API_KEY: <TOKEN>
As configurações de limite do token de acesso devem se sobrepor as do IP. Ex: Se o limite por IP é de 10 req/s e a de um determinado token é de 100 req/s, o rate limiter deve utilizar as informações do token.
Requisitos:

O rate limiter deve poder trabalhar como um middleware que é injetado ao servidor web
O rate limiter deve permitir a configuração do número máximo de requisições permitidas por segundo.
O rate limiter deve ter ter a opção de escolher o tempo de bloqueio do IP ou do Token caso a quantidade de requisições tenha sido excedida.
As configurações de limite devem ser realizadas via variáveis de ambiente ou em um arquivo “.env” na pasta raiz.
Deve ser possível configurar o rate limiter tanto para limitação por IP quanto por token de acesso.
O sistema deve responder adequadamente quando o limite é excedido:
Código HTTP: 429
Mensagem: you have reached the maximum number of requests or actions allowed within a certain time frame
Todas as informações de "limiter” devem ser armazenadas e consultadas de um banco de dados Redis. Você pode utilizar docker-compose para subir o Redis.
Crie uma “strategy” que permita trocar facilmente o Redis por outro mecanismo de persistência.
A lógica do limiter deve estar separada do middleware.
Exemplos:

Limitação por IP: Suponha que o rate limiter esteja configurado para permitir no máximo 5 requisições por segundo por IP. Se o IP 192.168.1.1 enviar 6 requisições em um segundo, a sexta requisição deve ser bloqueada.
Limitação por Token: Se um token abc123 tiver um limite configurado de 10 requisições por segundo e enviar 11 requisições nesse intervalo, a décima primeira deve ser bloqueada.
Nos dois casos acima, as próximas requisições poderão ser realizadas somente quando o tempo total de expiração ocorrer. Ex: Se o tempo de expiração é de 5 minutos, determinado IP poderá realizar novas requisições somente após os 5 minutos.
