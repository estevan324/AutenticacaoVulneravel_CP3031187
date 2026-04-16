# Vulnerabilidades em Microsserviços – Trechos de Código

Abaixo estão os trechos de código exatos onde cada vulnerabilidade se manifesta nos microsserviços gerados pelo script.

---

## 1. Broken Authentication (auth-service)

**Arquivo:** `auth-service/routes/auth.js`

### 🔓 JWT sem expiração e com segredo fraco

```javascript
// VULNERABILIDADE: segredo fraco, JWT sem expiração
const JWT_SECRET = process.env.JWT_SECRET || 'jwt_secret_fraca';

// ... dentro do login ...

// VULNERABILIDADE: token sem expiração, com segredo fraco
const token = jwt.sign(
  { id: user.id, username: user.username },
  JWT_SECRET
);
````

### Problemas identificados

* O token JWT é gerado **sem a opção `expiresIn`**, ou seja, nunca expira.
* Uso de **segredo fraco** (`jwt_secret_fraca`), facilmente previsível.
* **Ausência de refresh token**, impossibilitando rotação segura de credenciais.

---

## 2. BOLA (Broken Object Level Authorization) – product-service

**Arquivo:** `product-service/routes/products.js`

### 🧪 Criação de produto sem validação de ownership

```javascript
// Criar produto (BOLA: aceita qualquer userId, mesmo de outro usuário)
router.post('/', verifyToken, async (req, res) => {
  const { name, price, userId } = req.body;

  if (!name || !price || !userId) {
    return res.status(400).json({
      error: 'name, price e userId são obrigatórios'
    });
  }

  try {
    const [result] = await db.execute(
      'INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
      [name, price, userId]
    );

    res.status(201).json({
      id: result.insertId,
      name,
      price,
      userId
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Problema

* O `userId` vem diretamente de `req.body`.
* O sistema **não valida se `req.user.id === userId`**.
* Um atacante pode criar produtos em nome de qualquer usuário.

---

### 🧪 Operações sem verificação de propriedade

```javascript
// Listar todos os produtos (BOLA)
router.get('/', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM products');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buscar produto por ID (BOLA)
router.get('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await db.execute(
      'SELECT * FROM products WHERE id = ?',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar produto (BOLA)
router.put('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;

  try {
    const [result] = await db.execute(
      'UPDATE products SET name = ?, price = ? WHERE id = ?',
      [name, price, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    res.json({ message: 'Produto atualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deletar produto (BOLA)
router.delete('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await db.execute(
      'DELETE FROM products WHERE id = ?',
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Produto não encontrado' });
    }

    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Problema

* Nenhuma operação verifica `user_id = req.user.id`.
* Usuários autenticados podem:

  * Listar dados de terceiros
  * Atualizar produtos de outros usuários
  * Deletar recursos indevidamente

---

## 3. Improper Inventory Management – product-service

**Arquivo:** `product-service/routes/products.js`

### 🕳️ Endpoint interno não protegido

```javascript
// ===== IMPROPER INVENTORY MANAGEMENT =====
// Endpoint interno esquecido, não documentado, sem autenticação
router.get('/internal/debug', async (req, res) => {
  const [products] = await db.execute('SELECT * FROM products');
  const [users] = await db.execute(
    'SELECT id, name, price, user_id FROM products'
  );

  res.json({
    message: 'DEBUG ENDPOINT - Não usar em produção',
    total_products: products.length,
    products_sample: users.slice(0, 5),
    server_time: new Date().toISOString()
  });
});
```

### Problemas identificados

* Endpoint **não documentado** (shadow API).
* **Sem autenticação** (não utiliza `verifyToken`).
* Exposição de:

  * Volume de dados (`total_products`)
  * Amostra de registros
  * Timestamp do servidor
* Viola princípios de:

  * **Minimização de superfície de ataque**
  * **Segurança por design**

---

## Conclusão

Os trechos apresentados evidenciam três classes críticas de vulnerabilidades:

* **Broken Authentication:** falha na gestão de tokens e credenciais.
* **Broken Object Level Authorization (BOLA):** ausência de validação de propriedade.
* **Improper Inventory Management:** exposição de endpoints internos não protegidos.

Esses problemas são recorrentes em arquiteturas de microsserviços quando não há:

* centralização de políticas de segurança
* validação consistente de identidade e autorização
* governança de endpoints e versionamento de APIs


## Execução da aplicação

1) Execute npm install concurrently -D para instalar as bibliotecas
2) Execute todos os microsserviços npm run start