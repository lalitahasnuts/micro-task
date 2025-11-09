const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pino = require('pino-http');
const { z } = require('zod');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'my-key';

// In-memory storage (in production use database)
let users = [];
let requests = [];

// Middleware
app.use(pino({
  level: 'info',
  serializers: {
    req: (req) => ({
      method: req.method,
      url: req.url,
      headers: req.headers,
    }),
  },
}));

app.use(express.json());
app.use(cors());

// Add request tracking
app.use((req, res, next) => {
  const requestId = req.headers['x-request-id'] || uuidv4();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  
  requests.push({
    id: requestId,
    method: req.method,
    url: req.url,
    timestamp: new Date().toISOString(),
    userId: req.headers['x-user-id'] || null
  });
  
  next();
});

// Validation schemas
const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(2),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const updateProfileSchema = z.object({
  name: z.string().min(2).optional(),
});

// Authentication middleware
const authenticate = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Bearer token required'
        }
      });
    }
  
    const token = authHeader.replace('Bearer ', '');
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = users.find(u => u.id === decoded.userId);
      
      if (!user) {
        return res.status(401).json({
          success: false,
          error: {
            code: 'USER_NOT_FOUND', 
            message: 'User not found'
          }
        });
      }
      
      req.user = user;
      next();
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token'
        }
      });
    }
  };

const requireAdmin = (req, res, next) => {
  if (!req.user.roles.includes('admin')) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Admin access required'
      }
    });
  }
  next();
};

// Routes
// Register
app.post('/api/v1/register', async (req, res) => {
  try {
    const validatedData = registerSchema.parse(req.body);
    
    // Check if user already exists
    const existingUser = users.find(u => u.email === validatedData.email);
    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'USER_EXISTS',
          message: 'User with this email already exists'
        }
      });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(validatedData.password, 8);
    
    // Create user
    const user = {
      id: uuidv4(),
      email: validatedData.email,
      password: hashedPassword,
      name: validatedData.name,
      roles: ['user'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    users.push(user);
    
    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        roles: user.roles 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles,
          createdAt: user.createdAt
        },
        token
      }
    });
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid input data',
          details: error.errors
        }
      });
    }
    
    req.log.error('Registration error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
});

// Login
app.post('/api/v1/login', async (req, res) => {
  try {
    const validatedData = loginSchema.parse(req.body);
    
    // Find user
    const user = users.find(u => u.email === validatedData.email);
    if (!user) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      });
    }
    
    // Check password
    const isValidPassword = await bcrypt.compare(validatedData.password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid email or password'
        }
      });
    }
    
    // Generate JWT
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        roles: user.roles 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          roles: user.roles
        },
        token
      }
    });
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid input data',
          details: error.errors
        }
      });
    }
    
    req.log.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
});

// Get current profile
app.get('/api/v1/profile', authenticate, (req, res) => {
  res.json({
    success: true,
    data: {
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        roles: req.user.roles,
        createdAt: req.user.createdAt,
        updatedAt: req.user.updatedAt
      }
    }
  });
});

// Update profile
app.put('/api/v1/profile', authenticate, (req, res) => {
  try {
    const validatedData = updateProfileSchema.parse(req.body);
    
    // Update user
    const userIndex = users.findIndex(u => u.id === req.user.id);
    if (userIndex !== -1) {
      users[userIndex] = {
        ...users[userIndex],
        ...validatedData,
        updatedAt: new Date().toISOString()
      };
    }
    
    res.json({
      success: true,
      data: {
        user: {
          id: users[userIndex].id,
          email: users[userIndex].email,
          name: users[userIndex].name,
          roles: users[userIndex].roles,
          createdAt: users[userIndex].createdAt,
          updatedAt: users[userIndex].updatedAt
        }
      }
    });
    
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid input data',
          details: error.errors
        }
      });
    }
    
    req.log.error('Profile update error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
});

// Admin: List users
app.get('/api/v1/users', authenticate, requireAdmin, (req, res) => {
  const { page = 1, limit = 10, search } = req.query;
  const pageNum = parseInt(page);
  const limitNum = parseInt(limit);
  
  let filteredUsers = users;
  
  // Filter by search
  if (search) {
    filteredUsers = users.filter(user => 
      user.name.toLowerCase().includes(search.toLowerCase()) ||
      user.email.toLowerCase().includes(search.toLowerCase())
    );
  }
  
  // Pagination
  const startIndex = (pageNum - 1) * limitNum;
  const endIndex = startIndex + limitNum;
  const paginatedUsers = filteredUsers.slice(startIndex, endIndex);
  
  // Remove passwords from response
  const usersWithoutPasswords = paginatedUsers.map(user => ({
    id: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt
  }));
  
  res.json({
    success: true,
    data: {
      users: usersWithoutPasswords,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: filteredUsers.length,
        pages: Math.ceil(filteredUsers.length / limitNum)
      }
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'users-service',
    userCount: users.length
  });
});

// Debug endpoint to see requests
app.get('/api/v1/debug/requests', authenticate, requireAdmin, (req, res) => {
  res.json({
    success: true,
    data: {
      requests: requests.slice(-50) // Last 50 requests
    }
  });
});

app.listen(PORT, () => {
  console.log(`👥 Users service running on port ${PORT}`);
  
  // Create admin user for testing
  const createAdminUser = async () => {
    const hashedPassword = await bcrypt.hash('admin123', 12);
    users.push({
      id: uuidv4(),
      email: 'admin@example.com',
      password: hashedPassword,
      name: 'Admin User',
      roles: ['admin', 'user'],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    });
    console.log('✅ Admin user created: admin@example.com / admin123');
  };
  
  createAdminUser();
});

// Basic root route
app.get('/', (req, res) => {
    res.json({
      service: 'users-service',
      status: 'running',
      timestamp: new Date().toISOString(),
      endpoints: [
        'POST /api/v1/register',
        'POST /api/v1/login', 
        'GET /api/v1/profile',
        'PUT /api/v1/profile',
        'GET /api/v1/users (admin only)',
        'GET /health'
      ]
    });
  });