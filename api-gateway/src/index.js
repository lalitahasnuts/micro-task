const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Логирование
app.use('*', (req, res, next) => {
  console.log(`[GATEWAY] IN: ${req.method} ${req.originalUrl}`);
  next();
});

// User Service proxy с полным логированием
app.use('/api/v1/users', createProxyMiddleware({
    target: 'http://localhost:3001',
    changeOrigin: true,
    followRedirects: true,
    autoRewrite: true,
    protocolRewrite: 'http',
    headers: {
      'Connection': 'keep-alive'
    },
    onError: (err, req, res) => {
      console.error('[GATEWAY] Connection failed:', err.message);
      res.status(502).json({ 
        error: 'Service unavailable',
        message: 'Use direct connection: http://localhost:3001/api/v1/login'
      });
    }
  }));

app.listen(PORT, () => {
  console.log(`🚀 Gateway on port ${PORT}`);
});