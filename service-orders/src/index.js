import express from 'express';
import pino from 'pino-http';
import { z } from 'zod';
import { v4 as uuidv4 } from 'uuid';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3002;

// In-memory storage
let orders = [];
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

// Order statuses
const ORDER_STATUS = {
  CREATED: 'created',
  IN_PROGRESS: 'in_progress',
  COMPLETED: 'completed',
  CANCELLED: 'cancelled'
};

// Validation schemas
const createOrderSchema = z.object({
  items: z.array(z.object({
    product: z.string().min(1),
    quantity: z.number().int().positive(),
    price: z.number().positive()
  })).min(1),
  totalAmount: z.number().positive()
});

const updateOrderSchema = z.object({
  status: z.enum([ORDER_STATUS.IN_PROGRESS, ORDER_STATUS.COMPLETED, ORDER_STATUS.CANCELLED])
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role'];
  
  if (!userId) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required'
      }
    });
  }
  
  req.user = { id: userId, role: userRole };
  next();
};

// Authorization helpers
const canViewOrder = (order, userId, userRole) => {
  return order.userId === userId || userRole === 'admin';
};

const canUpdateOrder = (order, userId, userRole) => {
  return order.userId === userId || userRole === 'admin';
};

// Routes
// Create order
app.post('/api/v1/orders', authenticate, (req, res) => {
  try {
    const validatedData = createOrderSchema.parse(req.body);
    
    const order = {
      id: uuidv4(),
      userId: req.user.id,
      items: validatedData.items,
      totalAmount: validatedData.totalAmount,
      status: ORDER_STATUS.CREATED,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    orders.push(order);
    
    // Publish order created event (stub for future message broker)
    console.log(`📦 Order created: ${order.id} for user: ${req.user.id}`);
    
    res.status(201).json({
      success: true,
      data: {
        order: {
          id: order.id,
          userId: order.userId,
          items: order.items,
          totalAmount: order.totalAmount,
          status: order.status,
          createdAt: order.createdAt,
          updatedAt: order.updatedAt
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
    
    req.log.error('Create order error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
});

// Get order by ID
app.get('/api/v1/orders/:id', authenticate, (req, res) => {
  const order = orders.find(o => o.id === req.params.id);
  
  if (!order) {
    return res.status(404).json({
      success: false,
      error: {
        code: 'ORDER_NOT_FOUND',
        message: 'Order not found'
      }
    });
  }
  
  if (!canViewOrder(order, req.user.id, req.user.role)) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Access to this order is denied'
      }
    });
  }
  
  res.json({
    success: true,
    data: { order }
  });
});

// List user's orders
app.get('/api/v1/orders', authenticate, (req, res) => {
  const { page = 1, limit = 10, status, sort = 'createdAt' } = req.query;
  const pageNum = parseInt(page);
  const limitNum = parseInt(limit);
  
  let userOrders = orders;
  
  // Filter by user (unless admin)
  if (req.user.role !== 'admin') {
    userOrders = orders.filter(order => order.userId === req.user.id);
  }
  
  // Filter by status
  if (status) {
    userOrders = userOrders.filter(order => order.status === status);
  }
  
  // Sort orders
  userOrders.sort((a, b) => {
    if (sort === 'createdAt') {
      return new Date(b.createdAt) - new Date(a.createdAt);
    }
    if (sort === 'totalAmount') {
      return b.totalAmount - a.totalAmount;
    }
    return 0;
  });
  
  // Pagination
  const startIndex = (pageNum - 1) * limitNum;
  const endIndex = startIndex + limitNum;
  const paginatedOrders = userOrders.slice(startIndex, endIndex);
  
  res.json({
    success: true,
    data: {
      orders: paginatedOrders,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: userOrders.length,
        pages: Math.ceil(userOrders.length / limitNum)
      }
    }
  });
});

// Update order status
app.patch('/api/v1/orders/:id', authenticate, (req, res) => {
  try {
    const validatedData = updateOrderSchema.parse(req.body);
    
    const orderIndex = orders.findIndex(o => o.id === req.params.id);
    if (orderIndex === -1) {
      return res.status(404).json({
        success: false,
        error: {
          code: 'ORDER_NOT_FOUND',
          message: 'Order not found'
        }
      });
    }
    
    const order = orders[orderIndex];
    
    if (!canUpdateOrder(order, req.user.id, req.user.role)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'FORBIDDEN',
          message: 'Cannot update this order'
        }
      });
    }
    
    // Update order
    orders[orderIndex] = {
      ...order,
      status: validatedData.status,
      updatedAt: new Date().toISOString()
    };
    
    // Publish order updated event (stub for future message broker)
    console.log(`🔄 Order updated: ${order.id} - Status: ${validatedData.status}`);
    
    res.json({
      success: true,
      data: {
        order: orders[orderIndex]
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
    
    req.log.error('Update order error:', error);
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Internal server error'
      }
    });
  }
});

// Cancel order
app.delete('/api/v1/orders/:id', authenticate, (req, res) => {
  const orderIndex = orders.findIndex(o => o.id === req.params.id);
  
  if (orderIndex === -1) {
    return res.status(404).json({
      success: false,
      error: {
        code: 'ORDER_NOT_FOUND',
        message: 'Order not found'
      }
    });
  }
  
  const order = orders[orderIndex];
  
  if (!canUpdateOrder(order, req.user.id, req.user.role)) {
    return res.status(403).json({
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Cannot cancel this order'
      }
    });
  }
  
  // Update order status to cancelled instead of deleting
  orders[orderIndex] = {
    ...order,
    status: ORDER_STATUS.CANCELLED,
    updatedAt: new Date().toISOString()
  };
  
  console.log(`❌ Order cancelled: ${order.id}`);
  
  res.json({
    success: true,
    data: {
      message: 'Order cancelled successfully',
      order: orders[orderIndex]
    }
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    service: 'orders-service',
    orderCount: orders.length
  });
});

// Debug endpoint to see requests
app.get('/api/v1/debug/requests', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: {
        code: 'FORBIDDEN',
        message: 'Admin access required'
      }
    });
  }
  
  res.json({
    success: true,
    data: {
      requests: requests.slice(-50)
    }
  });
});

app.listen(PORT, () => {
  console.log(`📦 Orders service running on port ${PORT}`);
});