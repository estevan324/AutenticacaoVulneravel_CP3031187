const express = require('express');
const axios = require('axios');
const db = require('../db');
const router = express.Router();
require('dotenv').config();

// Middleware para validar token (chama auth-service)
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const response = await axios.post(`${process.env.AUTH_SERVICE_URL}/auth/verify`, { token });
    if (response.data.valid) {
      req.user = response.data.user;
      next();
    } else {
      res.status(401).json({ error: 'Token inválido' });
    }
  } catch (err) {
    res.status(401).json({ error: 'Falha na verificação do token' });
  }
};

// Middleware BOLA: NÃO verifica se o produto pertence ao usuário logado
// Qualquer usuário autenticado pode ver/alterar qualquer produto

// Listar todos os produtos (BOLA: retorna produtos de todos os usuários)
router.get('/', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT * FROM products');
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buscar produto por ID (BOLA: não verifica dono)
router.get('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await db.execute('SELECT * FROM products WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Criar produto (BOLA: aceita qualquer userId, mesmo de outro usuário)
router.post('/', verifyToken, async (req, res) => {
  const { name, price, userId } = req.body;
  if (!name || !price || !userId) {
    return res.status(400).json({ error: 'name, price e userId são obrigatórios' });
  }
  try {
    const [result] = await db.execute(
      'INSERT INTO products (name, price, user_id) VALUES (?, ?, ?)',
      [name, price, userId]
    );
    res.status(201).json({ id: result.insertId, name, price, userId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Atualizar produto (BOLA: não verifica ownership)
router.put('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  const { name, price } = req.body;
  try {
    const [result] = await db.execute(
      'UPDATE products SET name = ?, price = ? WHERE id = ?',
      [name, price, id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Produto não encontrado' });
    res.json({ message: 'Produto atualizado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deletar produto (BOLA: não verifica ownership)
router.delete('/:id', verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.execute('DELETE FROM products WHERE id = ?', [id]);
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Produto não encontrado' });
    res.status(204).send();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ===== IMPROPER INVENTORY MANAGEMENT =====
// Endpoint interno esquecido, não documentado, sem autenticação
router.get('/internal/debug', async (req, res) => {
  const [products] = await db.execute('SELECT * FROM products');
  const [users] = await db.execute('SELECT id, name, price, user_id FROM products');
  res.json({
    message: 'DEBUG ENDPOINT - Não usar em produção',
    total_products: products.length,
    products_sample: users.slice(0, 5),
    server_time: new Date().toISOString()
  });
});

module.exports = router;
