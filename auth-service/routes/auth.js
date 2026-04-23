const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("../db");
const router = express.Router();
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET; // agora obrigatório e forte
const REFRESH_SECRET = process.env.REFRESH_SECRET || JWT_SECRET; // idealmente outro segredo
// Gerar access token (curta duração)
function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: "15m" }, // ✅ expira em 15 minutos
  );
}
// Gerar refresh token (longa duração, armazenado)
function generateRefreshToken(user) {
  const refreshToken = jwt.sign(
    { id: user.id, type: "refresh" },
    REFRESH_SECRET,
    { expiresIn: "7d" },
  );
  return refreshToken;
}
// Registro (sem alteração)
router.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "..." });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const [result] = await db.execute(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed],
    );
    res.status(201).json({ id: result.insertId, username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Login – retorna access + refresh
router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.execute("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    if (rows.length === 0)
      return res.status(401).json({ error: "Credenciais inválidas" });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Credenciais inválidas" });
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    // Armazena refresh token no banco (associado ao usuário)
    await db.execute(
      "UPDATE users SET refresh_token = ? WHERE id = ?",

      [refreshToken, user.id],
    );
    res.json({ accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Renovação de access token
router.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(401).json({ error: "Refresh token obrigatório" });
  try {
    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    const [rows] = await db.execute(
      "SELECT * FROM users WHERE id = ? AND refresh_token = ?",
      [decoded.id, refreshToken],
    );
    if (rows.length === 0)
      return res.status(403).json({ error: "Refresh token inválido" });
    const user = rows[0];
    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);
    // Rotaciona refresh token
    await db.execute("UPDATE users SET refresh_token = ? WHERE id = ?", [
      newRefreshToken,
      user.id,
    ]);
    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (err) {
    res.status(403).json({ error: "Refresh token expirado ou inválido" });
  }
});
// Middleware de verificação (agora verifica expiração)
router.post("/verify", async (req, res) => {
  const token = req.body.token;
  if (!token) return res.status(401).json({ valid: false });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({
      valid: true,
      user: { id: decoded.id, username: decoded.username },
    });
  } catch (err) {
    res.status(401).json({ valid: false, error: err.message });
  }
});
module.exports = router;
