require('dotenv').config();
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Proxy para auth-service
app.use('/api/auth', createProxyMiddleware({
  target: process.env.AUTH_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/api/auth': '/auth' }
}));

// Proxy para product-service
app.use('/api/products', createProxyMiddleware({
  target: process.env.PRODUCT_SERVICE_URL,
  changeOrigin: true,
  pathRewrite: { '^/api/products': '/products' }
}));

app.listen(PORT, () => {
  console.log(`Gateway rodando na porta ${PORT}`);
  console.log(`Auth service -> ${process.env.AUTH_SERVICE_URL}`);
  console.log(`Product service -> ${process.env.PRODUCT_SERVICE_URL}`);
});
