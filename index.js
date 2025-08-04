// Cache-bust: 2025-08-03T18:25:00Z - Allow all CORS origins
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());

// CORS configuration - Allow all origins
app.use(cors({
  origin: true, // Allow all origins
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-vercel-protection-bypass'],
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
}));
app.use(morgan('combined'));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../dist')));

// Database initialization
const dbPath = path.join(__dirname, 'ims.db');
const db = new Database(dbPath);

// Initialize database tables
const initDatabase = () => {
  // Users table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      facility_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Facilities table
  db.exec(`
    CREATE TABLE IF NOT EXISTS facilities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      location TEXT,
      district TEXT,
      region TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Inventory items table
  db.exec(`
    CREATE TABLE IF NOT EXISTS inventory_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      category TEXT NOT NULL,
      sku TEXT UNIQUE NOT NULL,
      unit TEXT NOT NULL,
      current_stock INTEGER DEFAULT 0,
      min_stock INTEGER DEFAULT 0,
      max_stock INTEGER DEFAULT 0,
      cost REAL DEFAULT 0,
      supplier TEXT,
      facility_id INTEGER,
      location TEXT,
      expiry_date DATE,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (facility_id) REFERENCES facilities (id)
    )
  `);

  // Stock transactions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS stock_transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      item_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      unit TEXT NOT NULL,
      facility_id INTEGER NOT NULL,
      source TEXT,
      destination TEXT,
      reason TEXT NOT NULL,
      notes TEXT,
      user_id INTEGER NOT NULL,
      date DATE NOT NULL,
      time TIME NOT NULL,
      status TEXT DEFAULT 'completed',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (item_id) REFERENCES inventory_items (id),
      FOREIGN KEY (facility_id) REFERENCES facilities (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);

  // Transfers table
  db.exec(`
    CREATE TABLE IF NOT EXISTS transfers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      item_name TEXT NOT NULL,
      item_id INTEGER NOT NULL,
      quantity INTEGER NOT NULL,
      unit TEXT NOT NULL,
      from_facility_id INTEGER NOT NULL,
      to_facility_id INTEGER NOT NULL,
      requested_by INTEGER NOT NULL,
      request_date DATE NOT NULL,
      status TEXT DEFAULT 'pending',
      approved_by INTEGER,
      approval_date DATE,
      delivery_date DATE,
      reason TEXT NOT NULL,
      priority TEXT DEFAULT 'medium',
      notes TEXT,
      tracking_number TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (item_id) REFERENCES inventory_items (id),
      FOREIGN KEY (from_facility_id) REFERENCES facilities (id),
      FOREIGN KEY (to_facility_id) REFERENCES facilities (id),
      FOREIGN KEY (requested_by) REFERENCES users (id),
      FOREIGN KEY (approved_by) REFERENCES users (id)
    )
  `);

  // Insert default data
  insertDefaultData();
};

// Insert default data
const insertDefaultData = () => {
  // Check if data already exists
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (userCount.count === 0) {
    // Insert default users
    const defaultUsers = [
      { email: 'admin@ims.com', password: bcrypt.hashSync('admin123', 10), name: 'System Administrator', role: 'admin' },
      { email: 'regional@ims.com', password: bcrypt.hashSync('regional123', 10), name: 'Regional Manager', role: 'regional_manager' },
      { email: 'district@ims.com', password: bcrypt.hashSync('district123', 10), name: 'District Manager', role: 'district_manager' },
      { email: 'facility@ims.com', password: bcrypt.hashSync('facility123', 10), name: 'Facility Manager', role: 'facility_manager' },
      { email: 'worker@ims.com', password: bcrypt.hashSync('worker123', 10), name: 'Inventory Worker', role: 'inventory_worker' }
    ];

    const insertUser = db.prepare(`
      INSERT INTO users (email, password, name, role)
      VALUES (?, ?, ?, ?)
    `);

    defaultUsers.forEach(user => {
      insertUser.run(user.email, user.password, user.name, user.role);
    });

    // Insert default facilities
    const defaultFacilities = [
      { name: 'Main Warehouse', type: 'warehouse', location: 'Kampala', district: 'Kampala', region: 'Central' },
      { name: 'Distribution Center', type: 'distribution', location: 'Entebbe', district: 'Wakiso', region: 'Central' },
      { name: 'Regional Warehouse', type: 'warehouse', location: 'Jinja', district: 'Jinja', region: 'Eastern' },
      { name: 'Retail Store', type: 'retail', location: 'Mbarara', district: 'Mbarara', region: 'Western' }
    ];

    const insertFacility = db.prepare(`
      INSERT INTO facilities (name, type, location, district, region)
      VALUES (?, ?, ?, ?, ?)
    `);

    defaultFacilities.forEach(facility => {
      insertFacility.run(facility.name, facility.type, facility.location, facility.district, facility.region);
    });

    // Insert sample inventory items
    const sampleItems = [
      { name: 'Laptop Computers', description: 'High-performance laptops for office use', category: 'Electronics', sku: 'LAP-001', unit: 'units', current_stock: 45, min_stock: 20, max_stock: 100, cost: 1200000, supplier: 'Tech Supplies Ltd', location: 'A1-01', status: 'active' },
      { name: 'Office Chairs', description: 'Ergonomic office chairs', category: 'Furniture', sku: 'CHAIR-002', unit: 'pieces', current_stock: 120, min_stock: 50, max_stock: 200, cost: 150000, supplier: 'Furniture World', location: 'B2-03', status: 'active' },
      { name: 'Printer Paper', description: 'A4 printer paper, 80gsm', category: 'Office Supplies', sku: 'PAPER-003', unit: 'reams', current_stock: 85, min_stock: 30, max_stock: 150, cost: 25000, supplier: 'Paper Plus', location: 'C3-02', status: 'active' }
    ];

    const insertItem = db.prepare(`
      INSERT INTO inventory_items (name, description, category, sku, unit, current_stock, min_stock, max_stock, cost, supplier, location, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    sampleItems.forEach(item => {
      insertItem.run(item.name, item.description, item.category, item.sku, item.unit, item.current_stock, item.min_stock, item.max_stock, item.cost, item.supplier, item.location, item.status);
    });

    console.log('Default data inserted successfully');
  }
};

// Initialize database
initDatabase();

// Protection bypass middleware (for Vercel authentication)
const authenticateBypass = (req, res, next) => {
  const bypassSecret = req.headers['x-vercel-protection-bypass'] || req.query['x-vercel-protection-bypass'];
  
  if (bypassSecret === process.env.VERCEL_PROTECTION_BYPASS) {
    return next();
  }
  
  // Fallback to OIDC authentication
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (token && token.length > 10) {
      return next();
    }
  }
  
  return res.status(401).json({ error: 'Authentication required' });
};

// API Key authentication middleware (fallback)
const authenticateApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  if (apiKey !== process.env.API_KEY) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  next();
};

// Enhanced authentication middleware
const authenticateToken = (req, res, next) => {
  // Check for token in cookies first, then headers
  let token = req.cookies.token;
  
  if (!token) {
  const authHeader = req.headers['authorization'];
    token = authHeader && authHeader.split(' ')[1];
  }

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      // Clear invalid cookie
      res.clearCookie('token');
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Health check endpoint (no authentication required)
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    database: 'connected'
  });
});

// Enhanced authentication endpoints
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' } // Extended to 7 days
  );

  // Set secure cookie with extended options
  const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/'
  };

  res.cookie('token', token, cookieOptions);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    }
  });
});

// Logout endpoint
app.post('/api/logout', authenticateBypass, (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ success: true, message: 'Logged out successfully' });
});

// Check authentication status
app.get('/api/auth/status', authenticateBypass, authenticateToken, (req, res) => {
  res.json({
    authenticated: true,
    user: req.user
  });
});

// Users endpoints
app.get('/api/users', authenticateBypass, authenticateToken, (req, res) => {
  const users = db.prepare('SELECT id, email, name, role, created_at FROM users').all();
  res.json(users);
});

// Facilities endpoints
app.get('/api/facilities', authenticateBypass, authenticateToken, (req, res) => {
  const facilities = db.prepare('SELECT * FROM facilities ORDER BY name').all();
  res.json(facilities);
});

app.post('/api/facilities', authenticateBypass, authenticateToken, (req, res) => {
  const { name, type, location, district, region } = req.body;

  if (!name || !type) {
    return res.status(400).json({ error: 'Name and type required' });
  }

  try {
    const result = db.prepare(`
      INSERT INTO facilities (name, type, location, district, region)
      VALUES (?, ?, ?, ?, ?)
    `).run(name, type, location, district, region);

    res.json({ id: result.lastInsertRowid, message: 'Facility created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create facility' });
  }
});

// Inventory endpoints
app.get('/api/inventory', authenticateBypass, authenticateToken, (req, res) => {
  const items = db.prepare(`
    SELECT i.*, f.name as facility_name 
    FROM inventory_items i 
    LEFT JOIN facilities f ON i.facility_id = f.id 
    ORDER BY i.name
  `).all();
  res.json(items);
});

app.post('/api/inventory', authenticateBypass, authenticateToken, (req, res) => {
  const {
    name, description, category, sku, unit, current_stock, min_stock, max_stock,
    cost, supplier, facility_id, location, expiry_date, status
  } = req.body;

  if (!name || !sku || !category) {
    return res.status(400).json({ error: 'Name, SKU, and category required' });
  }

  try {
    const result = db.prepare(`
      INSERT INTO inventory_items (
        name, description, category, sku, unit, current_stock, min_stock, max_stock,
        cost, supplier, facility_id, location, expiry_date, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(name, description, category, sku, unit, current_stock || 0, min_stock || 0, max_stock || 0,
           cost || 0, supplier, facility_id, location, expiry_date, status || 'active');

    res.json({ id: result.lastInsertRowid, message: 'Inventory item created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create inventory item' });
  }
});

// Stock transactions endpoints
app.get('/api/transactions', authenticateBypass, authenticateToken, (req, res) => {
  const transactions = db.prepare(`
    SELECT t.*, i.name as item_name, f.name as facility_name, u.name as user_name
    FROM stock_transactions t
    LEFT JOIN inventory_items i ON t.item_id = i.id
    LEFT JOIN facilities f ON t.facility_id = f.id
    LEFT JOIN users u ON t.user_id = u.id
    ORDER BY t.created_at DESC
  `).all();
  res.json(transactions);
});

app.post('/api/transactions', authenticateBypass, authenticateToken, (req, res) => {
  const {
    type, item_id, quantity, unit, facility_id, source, destination,
    reason, notes, date, time, status
  } = req.body;

  if (!type || !item_id || !quantity || !facility_id || !reason) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Start transaction
    const transaction = db.transaction(() => {
      // Insert transaction
      const result = db.prepare(`
        INSERT INTO stock_transactions (
          type, item_id, quantity, unit, facility_id, source, destination,
          reason, notes, user_id, date, time, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(type, item_id, quantity, unit, facility_id, source, destination,
             reason, notes, req.user.id, date, time, status || 'completed');

      // Update inventory stock
      if (type === 'stock_in') {
        db.prepare(`
          UPDATE inventory_items 
          SET current_stock = current_stock + ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(quantity, item_id);
      } else if (type === 'stock_out') {
        db.prepare(`
          UPDATE inventory_items 
          SET current_stock = current_stock - ?, updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(quantity, item_id);
      }

      return result.lastInsertRowid;
    });

    const transactionId = transaction();
    res.json({ id: transactionId, message: 'Transaction created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});

// Transfers endpoints
app.get('/api/transfers', authenticateBypass, authenticateToken, (req, res) => {
  const transfers = db.prepare(`
    SELECT t.*, 
           f1.name as from_facility_name, f2.name as to_facility_name,
           u1.name as requested_by_name, u2.name as approved_by_name
    FROM transfers t
    LEFT JOIN facilities f1 ON t.from_facility_id = f1.id
    LEFT JOIN facilities f2 ON t.to_facility_id = f2.id
    LEFT JOIN users u1 ON t.requested_by = u1.id
    LEFT JOIN users u2 ON t.approved_by = u2.id
    ORDER BY t.created_at DESC
  `).all();
  res.json(transfers);
});

app.post('/api/transfers', authenticateBypass, authenticateToken, (req, res) => {
  const {
    item_name, item_id, quantity, unit, from_facility_id, to_facility_id,
    reason, priority, notes
  } = req.body;

  if (!item_name || !item_id || !quantity || !from_facility_id || !to_facility_id || !reason) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const result = db.prepare(`
      INSERT INTO transfers (
        item_name, item_id, quantity, unit, from_facility_id, to_facility_id,
        requested_by, reason, priority, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(item_name, item_id, quantity, unit, from_facility_id, to_facility_id,
           req.user.id, reason, priority || 'medium', notes);

    res.json({ id: result.lastInsertRowid, message: 'Transfer request created successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create transfer request' });
  }
});

// Update transfer status
app.put('/api/transfers/:id/status', authenticateBypass, authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status, approved_by } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status required' });
  }

  try {
    const result = db.prepare(`
      UPDATE transfers 
      SET status = ?, approved_by = ?, approval_date = CURRENT_DATE
      WHERE id = ?
    `).run(status, approved_by || req.user.id, id);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Transfer not found' });
    }

    res.json({ message: 'Transfer status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update transfer status' });
  }
});

// Reports endpoints
app.get('/api/reports/stock-levels', authenticateBypass, authenticateToken, (req, res) => {
  const stockLevels = db.prepare(`
    SELECT i.*, f.name as facility_name,
           CASE 
             WHEN i.current_stock <= i.min_stock THEN 'low'
             WHEN i.current_stock <= i.min_stock * 1.5 THEN 'warning'
             ELSE 'good'
           END as stock_status
    FROM inventory_items i
    LEFT JOIN facilities f ON i.facility_id = f.id
    WHERE i.status = 'active'
    ORDER BY i.current_stock ASC
  `).all();
  res.json(stockLevels);
});

app.get('/api/reports/consumption', authenticateBypass, authenticateToken, (req, res) => {
  const consumption = db.prepare(`
    SELECT 
      i.name as item_name,
      f.name as facility_name,
      SUM(CASE WHEN t.type = 'stock_in' THEN t.quantity ELSE 0 END) as total_in,
      SUM(CASE WHEN t.type = 'stock_out' THEN t.quantity ELSE 0 END) as total_out,
      (SUM(CASE WHEN t.type = 'stock_in' THEN t.quantity ELSE 0 END) - 
       SUM(CASE WHEN t.type = 'stock_out' THEN t.quantity ELSE 0 END)) as net_consumption
    FROM inventory_items i
    LEFT JOIN facilities f ON i.facility_id = f.id
    LEFT JOIN stock_transactions t ON i.id = t.item_id
    WHERE i.status = 'active'
    GROUP BY i.id, i.name, f.name
    ORDER BY net_consumption DESC
  `).all();
  res.json(consumption);
});

// Central Database endpoints
const CENTRAL_DB_PATH = path.join(__dirname, 'data', 'central_ims.db');

// Ensure data directory exists
const dataDir = path.dirname(CENTRAL_DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize central database
function initCentralDb() {
  if (!fs.existsSync(CENTRAL_DB_PATH)) {
    const centralDb = new Database(CENTRAL_DB_PATH);
    
    // Create schema for central database
    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        role TEXT NOT NULL CHECK (role IN ('admin', 'regional_manager', 'district_manager', 'facility_manager', 'inventory_worker')),
        facility_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS facilities (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('warehouse', 'distribution_center', 'retail_outlet')),
        region TEXT NOT NULL,
        district TEXT NOT NULL,
        address TEXT,
        gps_coordinates TEXT,
        contact_person TEXT,
        contact_phone TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive'))
      )
    `);

    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS inventory_items (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL,
        sku TEXT UNIQUE,
        unit TEXT NOT NULL,
        current_stock INTEGER DEFAULT 0,
        min_stock INTEGER DEFAULT 0,
        max_stock INTEGER DEFAULT 0,
        cost REAL DEFAULT 0,
        supplier TEXT,
        facility_id TEXT NOT NULL,
        location TEXT,
        expiry_date TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'discontinued')),
        FOREIGN KEY (facility_id) REFERENCES facilities (id)
      )
    `);

    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS stock_transactions (
        id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL,
        facility_id TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('stock_in', 'stock_out', 'transfer', 'adjustment')),
        quantity INTEGER NOT NULL,
        unit TEXT NOT NULL,
        source TEXT,
        destination TEXT,
        reason TEXT NOT NULL,
        notes TEXT,
        user_id TEXT NOT NULL,
        transaction_date TEXT NOT NULL,
        created_at TEXT NOT NULL,
        sync_status TEXT NOT NULL DEFAULT 'synced' CHECK (sync_status IN ('pending', 'synced', 'failed')),
        sync_attempts INTEGER DEFAULT 0,
        FOREIGN KEY (item_id) REFERENCES inventory_items (id),
        FOREIGN KEY (facility_id) REFERENCES facilities (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS transfers (
        id TEXT PRIMARY KEY,
        item_id TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        unit TEXT NOT NULL,
        from_facility_id TEXT NOT NULL,
        to_facility_id TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        request_date TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'in_transit', 'delivered', 'cancelled')),
        approved_by TEXT,
        approval_date TEXT,
        delivery_date TEXT,
        reason TEXT NOT NULL,
        priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
        notes TEXT,
        tracking_number TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        sync_status TEXT NOT NULL DEFAULT 'synced' CHECK (sync_status IN ('pending', 'synced', 'failed')),
        FOREIGN KEY (item_id) REFERENCES inventory_items (id),
        FOREIGN KEY (from_facility_id) REFERENCES facilities (id),
        FOREIGN KEY (to_facility_id) REFERENCES facilities (id),
        FOREIGN KEY (requested_by) REFERENCES users (id),
        FOREIGN KEY (approved_by) REFERENCES users (id)
      )
    `);

    centralDb.exec(`
      CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('stock_alert', 'transfer_update', 'system_notification')),
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        created_at TEXT NOT NULL,
        data TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Insert some initial data
    centralDb.exec(`
      INSERT OR IGNORE INTO users (id, name, email, phone, role, created_at, updated_at) 
      VALUES ('admin-1', 'Admin User', 'admin@ims.com', '+256700000000', 'admin', 
              datetime('now'), datetime('now'))
    `);
    
    centralDb.exec(`
      INSERT OR IGNORE INTO facilities (id, name, type, region, district, address, 
               contact_person, contact_phone, created_at, updated_at) 
      VALUES ('facility-1', 'Main Warehouse', 'warehouse', 'Central', 'Kampala', 
              'Kampala, Uganda', 'John Doe', '+256700000001', datetime('now'), datetime('now'))
    `);
    
    centralDb.exec(`
      INSERT OR IGNORE INTO inventory_items (id, name, description, category, sku, unit, 
               current_stock, min_stock, max_stock, cost, supplier, facility_id, location, 
               created_at, updated_at, status) 
      VALUES ('item-1', 'Paracetamol 500mg', 'Pain relief medication', 'Drugs', 'PAR001', 
              'Packs', 500, 50, 1000, 5000.00, 'Pharma Ltd', 'facility-1', 'Shelf A1', 
              datetime('now'), datetime('now'), 'active')
    `);

    centralDb.close();
    console.log('✅ Central database initialized');
  }
}

// Initialize central database
initCentralDb();

// Download central database
app.get('/api/central-db/download', authenticateBypass, authenticateToken, (req, res) => {
  try {
    if (!fs.existsSync(CENTRAL_DB_PATH)) {
      return res.status(404).json({ error: 'Central database not found' });
    }

    const dbBuffer = fs.readFileSync(CENTRAL_DB_PATH);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="central_ims.db"');
    res.setHeader('Content-Length', dbBuffer.length);
    res.send(dbBuffer);
    
    console.log('📥 Central database downloaded');
  } catch (error) {
    console.error('❌ Error downloading central database:', error);
    res.status(500).json({ error: 'Failed to download database' });
  }
});

// Upload database from client
app.post('/api/central-db/upload', authenticateBypass, authenticateToken, (req, res) => {
  try {
    // Handle the uploaded database
    const dbBuffer = Buffer.from(req.body.database || req.body);
    
    // Create backup of current database
    if (fs.existsSync(CENTRAL_DB_PATH)) {
      const backupPath = `${CENTRAL_DB_PATH}.backup.${Date.now()}`;
      fs.copyFileSync(CENTRAL_DB_PATH, backupPath);
      console.log(`💾 Backup created: ${backupPath}`);
    }

    // Write new database
    fs.writeFileSync(CENTRAL_DB_PATH, dbBuffer);
    
    console.log('📤 Central database uploaded successfully');
    res.json({ 
      success: true, 
      message: 'Database uploaded successfully',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Error uploading database:', error);
    res.status(500).json({ error: 'Failed to upload database' });
  }
});

// Serve React app for all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../dist/index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
});

module.exports = app; 