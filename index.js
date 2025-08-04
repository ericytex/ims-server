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

// Simple JSON-based storage
const DATA_FILE = path.join(__dirname, 'data', 'ims_data.json');

// Ensure data directory exists
const dataDir = path.dirname(DATA_FILE);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize data storage
let data = {
  users: [],
  facilities: [],
  inventory_items: [],
  stock_transactions: [],
  transfers: [],
  notifications: []
};

// Load data from file
const loadData = () => {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const fileData = fs.readFileSync(DATA_FILE, 'utf8');
      data = JSON.parse(fileData);
    }
  } catch (error) {
    console.error('Error loading data:', error);
  }
};

// Save data to file
const saveData = () => {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error saving data:', error);
  }
};

// Initialize database with default data
const initDatabase = () => {
  loadData();
  
  // Insert default data if no users exist
  if (data.users.length === 0) {
    const defaultUsers = [
      { id: 1, email: 'admin@ims.com', password: bcrypt.hashSync('admin123', 10), name: 'System Administrator', role: 'admin', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 2, email: 'regional@ims.com', password: bcrypt.hashSync('regional123', 10), name: 'Regional Manager', role: 'regional_manager', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 3, email: 'district@ims.com', password: bcrypt.hashSync('district123', 10), name: 'District Manager', role: 'district_manager', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 4, email: 'facility@ims.com', password: bcrypt.hashSync('facility123', 10), name: 'Facility Manager', role: 'facility_manager', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 5, email: 'worker@ims.com', password: bcrypt.hashSync('worker123', 10), name: 'Inventory Worker', role: 'inventory_worker', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
    ];

    const defaultFacilities = [
      { id: 1, name: 'Main Warehouse', type: 'warehouse', location: 'Kampala', district: 'Kampala', region: 'Central', created_at: new Date().toISOString() },
      { id: 2, name: 'Distribution Center', type: 'distribution', location: 'Entebbe', district: 'Wakiso', region: 'Central', created_at: new Date().toISOString() },
      { id: 3, name: 'Regional Warehouse', type: 'warehouse', location: 'Jinja', district: 'Jinja', region: 'Eastern', created_at: new Date().toISOString() },
      { id: 4, name: 'Retail Store', type: 'retail', location: 'Mbarara', district: 'Mbarara', region: 'Western', created_at: new Date().toISOString() }
    ];

    const sampleItems = [
      { id: 1, name: 'Laptop Computers', description: 'High-performance laptops for office use', category: 'Electronics', sku: 'LAP-001', unit: 'units', current_stock: 45, min_stock: 20, max_stock: 100, cost: 1200000, supplier: 'Tech Supplies Ltd', location: 'A1-01', status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 2, name: 'Office Chairs', description: 'Ergonomic office chairs', category: 'Furniture', sku: 'CHAIR-002', unit: 'pieces', current_stock: 120, min_stock: 50, max_stock: 200, cost: 150000, supplier: 'Furniture World', location: 'B2-03', status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
      { id: 3, name: 'Printer Paper', description: 'A4 printer paper, 80gsm', category: 'Office Supplies', sku: 'PAPER-003', unit: 'reams', current_stock: 85, min_stock: 30, max_stock: 150, cost: 25000, supplier: 'Paper Plus', location: 'C3-02', status: 'active', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
    ];

    data.users = defaultUsers;
    data.facilities = defaultFacilities;
    data.inventory_items = sampleItems;
    
    saveData();
    console.log('Default data inserted successfully');
  }
  
  console.log('Database initialized successfully');
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

  const user = data.users.find(u => u.email === email);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' } // Extended to 7 days
  );

  // Set HTTP-only cookie
  res.cookie('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({
    message: 'Login successful',
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    },
    token: token
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
  res.json(data.users);
});

// Facilities endpoints
app.get('/api/facilities', authenticateBypass, authenticateToken, (req, res) => {
  res.json(data.facilities);
});

app.post('/api/facilities', authenticateBypass, authenticateToken, (req, res) => {
  const { name, type, location, district, region } = req.body;

  if (!name || !type) {
    return res.status(400).json({ error: 'Name and type required' });
  }

  const newFacility = {
    id: data.facilities.length + 1, // Simple ID generation
    name,
    type,
    location,
    district,
    region,
    created_at: new Date().toISOString()
  };

  data.facilities.push(newFacility);
  saveData();
  res.json({ id: newFacility.id, message: 'Facility created successfully' });
});

// Inventory endpoints
app.get('/api/inventory', authenticateBypass, authenticateToken, (req, res) => {
  const items = data.inventory_items.map(item => ({
    ...item,
    facility_name: data.facilities.find(f => f.id === item.facility_id)?.name || 'N/A'
  }));
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

  const newItem = {
    id: data.inventory_items.length + 1, // Simple ID generation
    name,
    description,
    category,
    sku,
    unit,
    current_stock: current_stock || 0,
    min_stock: min_stock || 0,
    max_stock: max_stock || 0,
    cost: cost || 0,
    supplier,
    facility_id,
    location,
    expiry_date,
    status: status || 'active',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  data.inventory_items.push(newItem);
  saveData();
  res.json({ id: newItem.id, message: 'Inventory item created successfully' });
});

// Stock transactions endpoints
app.get('/api/transactions', authenticateBypass, authenticateToken, (req, res) => {
  const transactions = data.stock_transactions.map(t => ({
    ...t,
    item_name: data.inventory_items.find(i => i.id === t.item_id)?.name || 'N/A',
    facility_name: data.facilities.find(f => f.id === t.facility_id)?.name || 'N/A',
    user_name: data.users.find(u => u.id === t.user_id)?.name || 'N/A'
  }));
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

  const newTransaction = {
    id: data.stock_transactions.length + 1, // Simple ID generation
    type,
    item_id,
    quantity,
    unit,
    facility_id,
    source,
    destination,
    reason,
    notes,
    user_id: req.user.id,
    date: date || new Date().toISOString().split('T')[0],
    time: time || new Date().toISOString().split('T')[1],
    status: status || 'completed',
    created_at: new Date().toISOString()
  };

  data.stock_transactions.push(newTransaction);
  saveData();
  res.json({ id: newTransaction.id, message: 'Transaction created successfully' });
});

// Transfers endpoints
app.get('/api/transfers', authenticateBypass, authenticateToken, (req, res) => {
  const transfers = data.transfers.map(t => ({
    ...t,
    from_facility_name: data.facilities.find(f => f.id === t.from_facility_id)?.name || 'N/A',
    to_facility_name: data.facilities.find(f => f.id === t.to_facility_id)?.name || 'N/A',
    requested_by_name: data.users.find(u => u.id === t.requested_by)?.name || 'N/A',
    approved_by_name: data.users.find(u => u.id === t.approved_by)?.name || 'N/A'
  }));
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

  const newTransfer = {
    id: data.transfers.length + 1, // Simple ID generation
    item_name,
    item_id,
    quantity,
    unit,
    from_facility_id,
    to_facility_id,
    requested_by: req.user.id,
    request_date: new Date().toISOString().split('T')[0],
    status: 'pending',
    approved_by: null,
    approval_date: null,
    delivery_date: null,
    reason,
    priority: priority || 'medium',
    notes,
    tracking_number: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  data.transfers.push(newTransfer);
  saveData();
  res.json({ id: newTransfer.id, message: 'Transfer request created successfully' });
});

// Update transfer status
app.put('/api/transfers/:id/status', authenticateBypass, authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status, approved_by } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status required' });
  }

  const transferIndex = data.transfers.findIndex(t => t.id === parseInt(id));
  if (transferIndex === -1) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  const updatedTransfer = {
    ...data.transfers[transferIndex],
    status,
    approved_by: approved_by || req.user.id,
    approval_date: new Date().toISOString().split('T')[0]
  };

  data.transfers[transferIndex] = updatedTransfer;
  saveData();
  res.json({ message: 'Transfer status updated successfully' });
});

// Reports endpoints
app.get('/api/reports/stock-levels', authenticateBypass, authenticateToken, (req, res) => {
  const stockLevels = data.inventory_items.map(item => ({
    ...item,
    facility_name: data.facilities.find(f => f.id === item.facility_id)?.name || 'N/A',
    stock_status: (item.current_stock <= item.min_stock) ? 'low' :
                   (item.current_stock <= item.min_stock * 1.5) ? 'warning' : 'good'
  }));
  res.json(stockLevels);
});

app.get('/api/reports/consumption', authenticateBypass, authenticateToken, (req, res) => {
  const consumption = data.inventory_items.map(item => ({
    ...item,
    facility_name: data.facilities.find(f => f.id === item.facility_id)?.name || 'N/A',
    total_in: data.stock_transactions.filter(t => t.item_id === item.id && t.type === 'stock_in').reduce((sum, t) => sum + t.quantity, 0),
    total_out: data.stock_transactions.filter(t => t.item_id === item.id && t.type === 'stock_out').reduce((sum, t) => sum + t.quantity, 0),
    net_consumption: data.stock_transactions.filter(t => t.item_id === item.id).reduce((sum, t) => {
      if (t.type === 'stock_in') sum += t.quantity;
      if (t.type === 'stock_out') sum -= t.quantity;
      return sum;
    }, 0)
  }));
  res.json(consumption);
});

// Central Database endpoints
const CENTRAL_DATA_FILE = path.join(__dirname, 'data', 'central_ims_data.json');

// Ensure central data directory exists
const centralDataDir = path.dirname(CENTRAL_DATA_FILE);
if (!fs.existsSync(centralDataDir)) {
  fs.mkdirSync(centralDataDir, { recursive: true });
}

// Initialize central database with JSON storage
function initCentralDb() {
  try {
    if (!fs.existsSync(CENTRAL_DATA_FILE)) {
      const centralData = {
        users: [
          { id: 'admin-1', name: 'Admin User', email: 'admin@ims.com', phone: '+256700000000', role: 'admin', created_at: new Date().toISOString(), updated_at: new Date().toISOString() }
        ],
        facilities: [
          { id: 'facility-1', name: 'Main Warehouse', type: 'warehouse', region: 'Central', district: 'Kampala', address: 'Kampala, Uganda', contact_person: 'John Doe', contact_phone: '+256700000001', created_at: new Date().toISOString(), updated_at: new Date().toISOString(), status: 'active' }
        ],
        inventory_items: [
          { id: 'item-1', name: 'Paracetamol 500mg', description: 'Pain relief medication', category: 'Drugs', sku: 'PAR001', unit: 'Packs', current_stock: 500, min_stock: 50, max_stock: 1000, cost: 5000.00, supplier: 'Pharma Ltd', facility_id: 'facility-1', location: 'Shelf A1', created_at: new Date().toISOString(), updated_at: new Date().toISOString(), status: 'active' }
        ],
        stock_transactions: [],
        transfers: [],
        notifications: []
      };
      
      fs.writeFileSync(CENTRAL_DATA_FILE, JSON.stringify(centralData, null, 2));
      console.log('✅ Central database initialized');
    }
  } catch (error) {
    console.error('❌ Error initializing central database:', error);
  }
}

// Initialize central database
initCentralDb();

// Download central database
app.get('/api/central-db/download', authenticateBypass, authenticateToken, (req, res) => {
  try {
    if (!fs.existsSync(CENTRAL_DATA_FILE)) {
      return res.status(404).json({ error: 'Central database not found' });
    }

    const centralData = fs.readFileSync(CENTRAL_DATA_FILE, 'utf8');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="central_ims_data.json"');
    res.send(centralData);
    
    console.log('📥 Central database downloaded');
  } catch (error) {
    console.error('❌ Error downloading central database:', error);
    res.status(500).json({ error: 'Failed to download database' });
  }
});

// Upload database from client
app.post('/api/central-db/upload', authenticateBypass, authenticateToken, (req, res) => {
  try {
    // Handle the uploaded database data
    const uploadedData = req.body.database || req.body;
    
    // Create backup of current database
    if (fs.existsSync(CENTRAL_DATA_FILE)) {
      const backupPath = `${CENTRAL_DATA_FILE}.backup.${Date.now()}`;
      fs.copyFileSync(CENTRAL_DATA_FILE, backupPath);
      console.log(`💾 Backup created: ${backupPath}`);
    }

    // Write new database
    fs.writeFileSync(CENTRAL_DATA_FILE, JSON.stringify(uploadedData, null, 2));
    
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