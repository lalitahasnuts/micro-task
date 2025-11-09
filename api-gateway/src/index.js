const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const pino = require('pino-http');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Middleware
app.use(pino({
  level: 'info',
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: req.headers,
    }),
    res: (res) => ({
      statusCode: res.statusCode,
    }),
  },
}));

app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Access token required'
      }
    });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid or expired token'
      }
    });
  }
};

// Add X-Request-ID to headers
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || uuidv4();
  req.headers['x-request-id'] = requestId;
  res.setHeader('X-Request-ID', requestId);
  next();
});

// Basic root route - ДОБАВЬТЕ ЭТОТ МАРШРУТ
app.get('/', (req, res) => {
  res.json({
    service: 'api-gateway',
    status: 'running',
    timestamp: new Date().toISOString(),
    endpoints: [
      'POST /api/v1/users/auth/register',
      'POST /api/v1/users/auth/login',
      'GET /api/v1/users/profile',
      'PUT /api/v1/users/profile',
      'GET /api/v1/users (admin only)',
      'POST /api/v1/orders',
      'GET /api/v1/orders',
      'GET /api/v1/orders/:id',
      'PATCH /api/v1/orders/:id',
      'DELETE /api/v1/orders/:id',
      'GET /health'
    ],
    note: 'Use Authorization: Bearer <token> for protected routes'
  });
});

// Proxy configuration
const usersServiceProxy = createProxyMiddleware({
  target: process.env.USERS_SERVICE_URL || 'http://localhost:3001',
  changeOrigin: true,
  pathRewrite: {
    '^/api/v1/users': '/api/v1',
  },
  onProxyReq: (proxyReq, req) => {
    if (req.user) {
      proxyReq.setHeader('X-User-ID', req.user.userId);
      proxyReq.setHeader('X-User-Role', req.user.role);
    }
  },
});

const ordersServiceProxy = createProxyMiddleware({
  target: process.env.ORDERS_SERVICE_URL || 'http://localhost:3002',
  changeOrigin: true,
  pathRewrite: {
    '^/api/v1/orders': '/api/v1',
  },
  onProxyReq: (proxyReq, req) => {
    if (req.user) {
      proxyReq.setHeader('X-User-ID', req.user.userId);
      proxyReq.setHeader('X-User-Role', req.user.role);
    }
  },
});

// Public routes
app.use('/api/v1/users/auth', usersServiceProxy);

// Protected routes
app.use('/api/v1/users', authenticateToken, usersServiceProxy);
app.use('/api/v1/orders', authenticateToken, ordersServiceProxy);

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', service: 'api-gateway' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: 'Route not found'
    }
  });
});

app.listen(PORT, () => {
  console.log(`🚀 API Gateway running on port ${PORT}`);
});