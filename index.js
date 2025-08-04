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
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3001;

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL || 'https://your-project.supabase.co';
const supabaseKey = process.env.SUPABASE_ANON_KEY || 'your-anon-key';
const supabase = createClient(supabaseUrl, supabaseKey);

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

// Initialize database with default data
const initDatabase = async () => {
  try {
    // Check if users exist
    const { data: users, error: usersError } = await supabase
      .from('users')
      .select('*')
      .limit(1);

    if (usersError) {
      console.error('Error checking users:', usersError);
      return;
    }

    // Insert default data if no users exist
    if (!users || users.length === 0) {
      const defaultUsers = [
        { email: 'admin@ims.com', password: bcrypt.hashSync('admin123', 10), name: 'System Administrator', role: 'admin' },
        { email: 'regional@ims.com', password: bcrypt.hashSync('regional123', 10), name: 'Regional Manager', role: 'regional_manager' },
        { email: 'district@ims.com', password: bcrypt.hashSync('district123', 10), name: 'District Manager', role: 'district_manager' },
        { email: 'facility@ims.com', password: bcrypt.hashSync('facility123', 10), name: 'Facility Manager', role: 'facility_manager' },
        { email: 'worker@ims.com', password: bcrypt.hashSync('worker123', 10), name: 'Inventory Worker', role: 'inventory_worker' }
      ];

      const { error: insertUsersError } = await supabase
        .from('users')
        .insert(defaultUsers);

      if (insertUsersError) {
        console.error('Error inserting default users:', insertUsersError);
        return;
      }

      const defaultFacilities = [
        { name: 'Main Warehouse', type: 'warehouse', location: 'Kampala', district: 'Kampala', region: 'Central' },
        { name: 'Distribution Center', type: 'distribution', location: 'Entebbe', district: 'Wakiso', region: 'Central' },
        { name: 'Regional Warehouse', type: 'warehouse', location: 'Jinja', district: 'Jinja', region: 'Eastern' },
        { name: 'Retail Store', type: 'retail', location: 'Mbarara', district: 'Mbarara', region: 'Western' }
      ];

      const { error: insertFacilitiesError } = await supabase
        .from('facilities')
        .insert(defaultFacilities);

      if (insertFacilitiesError) {
        console.error('Error inserting default facilities:', insertFacilitiesError);
        return;
      }

      const sampleItems = [
        { name: 'Laptop Computers', description: 'High-performance laptops for office use', category: 'Electronics', sku: 'LAP-001', unit: 'units', current_stock: 45, min_stock: 20, max_stock: 100, cost: 1200000, supplier: 'Tech Supplies Ltd', location: 'A1-01', status: 'active' },
        { name: 'Office Chairs', description: 'Ergonomic office chairs', category: 'Furniture', sku: 'CHAIR-002', unit: 'pieces', current_stock: 120, min_stock: 50, max_stock: 200, cost: 150000, supplier: 'Furniture World', location: 'B2-03', status: 'active' },
        { name: 'Printer Paper', description: 'A4 printer paper, 80gsm', category: 'Office Supplies', sku: 'PAPER-003', unit: 'reams', current_stock: 85, min_stock: 30, max_stock: 150, cost: 25000, supplier: 'Paper Plus', location: 'C3-02', status: 'active' }
      ];

      const { error: insertItemsError } = await supabase
        .from('inventory_items')
        .insert(sampleItems);

      if (insertItemsError) {
        console.error('Error inserting sample items:', insertItemsError);
        return;
      }

      console.log('Default data inserted successfully');
    }
    
    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
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
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  const { data: users, error: usersError } = await supabase
    .from('users')
    .select('*')
    .eq('email', email);

  if (usersError || !users || users.length === 0) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const user = users[0];

  if (!bcrypt.compareSync(password, user.password)) {
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
app.get('/api/users', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: users, error: usersError } = await supabase
    .from('users')
    .select('*');

  if (usersError) {
    console.error('Error fetching users:', usersError);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
  res.json(users);
});

// Facilities endpoints
app.get('/api/facilities', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: facilities, error: facilitiesError } = await supabase
    .from('facilities')
    .select('*');

  if (facilitiesError) {
    console.error('Error fetching facilities:', facilitiesError);
    return res.status(500).json({ error: 'Failed to fetch facilities' });
  }
  res.json(facilities);
});

app.post('/api/facilities', authenticateBypass, authenticateToken, async (req, res) => {
  const { name, type, location, district, region } = req.body;

  if (!name || !type || !location || !district || !region) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const newFacility = {
    name,
    type,
    location,
    district,
    region,
    created_at: new Date().toISOString()
  };

  const { data: insertedFacility, error: insertError } = await supabase
    .from('facilities')
    .insert([newFacility]);

  if (insertError) {
    console.error('Error creating facility:', insertError);
    return res.status(500).json({ error: 'Failed to create facility' });
  }
  res.json({ id: insertedFacility[0].id, message: 'Facility created successfully' });
});

// Inventory endpoints
app.get('/api/inventory', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: inventoryItems, error: inventoryError } = await supabase
    .from('inventory_items')
    .select('*');

  if (inventoryError) {
    console.error('Error fetching inventory items:', inventoryError);
    return res.status(500).json({ error: 'Failed to fetch inventory items' });
  }
  
  const items = await Promise.all(inventoryItems.map(async (item) => {
    const facilityName = item.facility_id ? 
      (await supabase.from('facilities').select('name').eq('id', item.facility_id).single()).data?.name || 'N/A' : 
      'N/A';
    return {
      ...item,
      facility_name: facilityName
    };
  }));
  
  res.json(items);
});

app.post('/api/inventory', authenticateBypass, authenticateToken, async (req, res) => {
  const { name, description, category, sku, unit, current_stock, min_stock, max_stock, cost, supplier, facility_id, location, expiry_date, status } = req.body;

  if (!name || !category || !sku || !unit) {
    return res.status(400).json({ error: 'Name, category, SKU, and unit are required' });
  }

  const newItem = {
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

  const { data: insertedItem, error: insertError } = await supabase
    .from('inventory_items')
    .insert([newItem]);

  if (insertError) {
    console.error('Error creating inventory item:', insertError);
    return res.status(500).json({ error: 'Failed to create inventory item' });
  }
  res.json({ id: insertedItem[0].id, message: 'Inventory item created successfully' });
});

// Stock transactions endpoints
app.get('/api/transactions', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: stockTransactions, error: transactionsError } = await supabase
    .from('stock_transactions')
    .select('*');

  if (transactionsError) {
    console.error('Error fetching stock transactions:', transactionsError);
    return res.status(500).json({ error: 'Failed to fetch stock transactions' });
  }
  
  const transactions = await Promise.all(stockTransactions.map(async (t) => {
    const [itemResult, facilityResult, userResult] = await Promise.all([
      supabase.from('inventory_items').select('name').eq('id', t.item_id).single(),
      supabase.from('facilities').select('name').eq('id', t.facility_id).single(),
      supabase.from('users').select('name').eq('id', t.user_id).single()
    ]);
    
    return {
      ...t,
      item_name: itemResult.data?.name || 'N/A',
      facility_name: facilityResult.data?.name || 'N/A',
      user_name: userResult.data?.name || 'N/A'
    };
  }));
  
  res.json(transactions);
});

app.post('/api/transactions', authenticateBypass, authenticateToken, async (req, res) => {
  const { type, item_id, quantity, unit, facility_id, source, destination, reason, notes, date, time, status } = req.body;

  if (!type || !item_id || !quantity || !unit || !facility_id || !reason) {
    return res.status(400).json({ error: 'Type, item_id, quantity, unit, facility_id, and reason are required' });
  }

  const newTransaction = {
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

  const { data: insertedTransaction, error: insertError } = await supabase
    .from('stock_transactions')
    .insert([newTransaction]);

  if (insertError) {
    console.error('Error creating stock transaction:', insertError);
    return res.status(500).json({ error: 'Failed to create stock transaction' });
  }
  res.json({ id: insertedTransaction[0].id, message: 'Transaction created successfully' });
});

// Transfers endpoints
app.get('/api/transfers', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: transfers, error: transfersError } = await supabase
    .from('transfers')
    .select('*');

  if (transfersError) {
    console.error('Error fetching transfers:', transfersError);
    return res.status(500).json({ error: 'Failed to fetch transfers' });
  }
  
  const transfersWithNames = await Promise.all(transfers.map(async (t) => {
    const [fromFacilityResult, toFacilityResult, requestedByResult, approvedByResult] = await Promise.all([
      supabase.from('facilities').select('name').eq('id', t.from_facility_id).single(),
      supabase.from('facilities').select('name').eq('id', t.to_facility_id).single(),
      supabase.from('users').select('name').eq('id', t.requested_by).single(),
      t.approved_by ? supabase.from('users').select('name').eq('id', t.approved_by).single() : Promise.resolve({ data: null })
    ]);
    
    return {
      ...t,
      from_facility_name: fromFacilityResult.data?.name || 'N/A',
      to_facility_name: toFacilityResult.data?.name || 'N/A',
      requested_by_name: requestedByResult.data?.name || 'N/A',
      approved_by_name: approvedByResult.data?.name || 'N/A'
    };
  }));
  
  res.json(transfersWithNames);
});

app.post('/api/transfers', authenticateBypass, authenticateToken, async (req, res) => {
  const { item_name, item_id, quantity, unit, from_facility_id, to_facility_id, reason, priority, notes } = req.body;

  if (!item_name || !item_id || !quantity || !unit || !from_facility_id || !to_facility_id || !reason) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  const newTransfer = {
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

  const { data: insertedTransfer, error: insertError } = await supabase
    .from('transfers')
    .insert([newTransfer]);

  if (insertError) {
    console.error('Error creating transfer:', insertError);
    return res.status(500).json({ error: 'Failed to create transfer' });
  }
  res.json({ id: insertedTransfer[0].id, message: 'Transfer request created successfully' });
});

app.put('/api/transfers/:id/status', authenticateBypass, authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, approved_by } = req.body;

  if (!status) {
    return res.status(400).json({ error: 'Status is required' });
  }

  const { data: updatedTransfer, error: updateError } = await supabase
    .from('transfers')
    .update({ status, approved_by: approved_by || req.user.id, approval_date: new Date().toISOString().split('T')[0] })
    .eq('id', parseInt(id))
    .select()
    .single();

  if (updateError) {
    console.error('Error updating transfer status:', updateError);
    return res.status(500).json({ error: 'Failed to update transfer status' });
  }
  res.json({ message: 'Transfer status updated successfully' });
});

// Reports endpoints
app.get('/api/reports/stock-levels', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: inventoryItems, error: inventoryError } = await supabase
    .from('inventory_items')
    .select('*');

  if (inventoryError) {
    console.error('Error fetching inventory items for stock levels:', inventoryError);
    return res.status(500).json({ error: 'Failed to fetch inventory items for stock levels' });
  }
  
  const stockLevels = await Promise.all(inventoryItems.map(async (item) => {
    const facilityName = item.facility_id ? 
      (await supabase.from('facilities').select('name').eq('id', item.facility_id).single()).data?.name || 'N/A' : 
      'N/A';
    return {
      ...item,
      facility_name: facilityName,
      stock_status: (item.current_stock <= item.min_stock) ? 'low' :
                     (item.current_stock <= item.min_stock * 1.5) ? 'warning' : 'good'
    };
  }));
  
  res.json(stockLevels);
});

app.get('/api/reports/consumption', authenticateBypass, authenticateToken, async (req, res) => {
  const { data: inventoryItems, error: inventoryError } = await supabase
    .from('inventory_items')
    .select('*');

  if (inventoryError) {
    console.error('Error fetching inventory items for consumption:', inventoryError);
    return res.status(500).json({ error: 'Failed to fetch inventory items for consumption' });
  }
  
  const consumption = await Promise.all(inventoryItems.map(async (item) => {
    const [facilityResult, stockInResult, stockOutResult, allTransactionsResult] = await Promise.all([
      item.facility_id ? supabase.from('facilities').select('name').eq('id', item.facility_id).single() : Promise.resolve({ data: null }),
      supabase.from('stock_transactions').select('quantity').eq('item_id', item.id).eq('type', 'stock_in'),
      supabase.from('stock_transactions').select('quantity').eq('item_id', item.id).eq('type', 'stock_out'),
      supabase.from('stock_transactions').select('quantity, type').eq('item_id', item.id)
    ]);
    
    const totalIn = stockInResult.data?.reduce((sum, t) => sum + t.quantity, 0) || 0;
    const totalOut = stockOutResult.data?.reduce((sum, t) => sum + t.quantity, 0) || 0;
    const netConsumption = allTransactionsResult.data?.reduce((sum, t) => {
      if (t.type === 'stock_in') sum += t.quantity;
      if (t.type === 'stock_out') sum -= t.quantity;
      return sum;
    }, 0) || 0;
    
    return {
      ...item,
      facility_name: facilityResult.data?.name || 'N/A',
      total_in: totalIn,
      total_out: totalOut,
      net_consumption: netConsumption
    };
  }));
  
  res.json(consumption);
});

// Central Database endpoints
app.get('/api/central-db/download', authenticateBypass, authenticateToken, async (req, res) => {
  try {
    // Fetch all data from Supabase
    const [usersResult, facilitiesResult, inventoryResult, transactionsResult, transfersResult] = await Promise.all([
      supabase.from('users').select('*'),
      supabase.from('facilities').select('*'),
      supabase.from('inventory_items').select('*'),
      supabase.from('stock_transactions').select('*'),
      supabase.from('transfers').select('*')
    ]);

    if (usersResult.error || facilitiesResult.error || inventoryResult.error || transactionsResult.error || transfersResult.error) {
      console.error('Error fetching central data:', { 
        usersError: usersResult.error, 
        facilitiesError: facilitiesResult.error, 
        inventoryError: inventoryResult.error, 
        transactionsError: transactionsResult.error, 
        transfersError: transfersResult.error 
      });
      return res.status(500).json({ error: 'Failed to fetch central data' });
    }

    const centralData = {
      users: usersResult.data || [],
      facilities: facilitiesResult.data || [],
      inventory_items: inventoryResult.data || [],
      stock_transactions: transactionsResult.data || [],
      transfers: transfersResult.data || [],
      timestamp: new Date().toISOString()
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="central_ims_data.json"');
    res.send(JSON.stringify(centralData, null, 2));
    
    console.log('📥 Central database downloaded');
  } catch (error) {
    console.error('❌ Error downloading central database:', error);
    res.status(500).json({ error: 'Failed to download database' });
  }
});

// Upload database from client
app.post('/api/central-db/upload', authenticateBypass, authenticateToken, async (req, res) => {
  try {
    const uploadedData = req.body.database || req.body;
    
    if (!uploadedData || typeof uploadedData !== 'object') {
      return res.status(400).json({ error: 'Invalid data format' });
    }

    // Clear existing data and insert new data
    const clearPromises = [
      supabase.from('users').delete().neq('id', 0),
      supabase.from('facilities').delete().neq('id', 0),
      supabase.from('inventory_items').delete().neq('id', 0),
      supabase.from('stock_transactions').delete().neq('id', 0),
      supabase.from('transfers').delete().neq('id', 0)
    ];

    await Promise.all(clearPromises);

    // Insert new data
    const insertPromises = [];
    
    if (uploadedData.users && uploadedData.users.length > 0) {
      insertPromises.push(supabase.from('users').insert(uploadedData.users));
    }
    
    if (uploadedData.facilities && uploadedData.facilities.length > 0) {
      insertPromises.push(supabase.from('facilities').insert(uploadedData.facilities));
    }
    
    if (uploadedData.inventory_items && uploadedData.inventory_items.length > 0) {
      insertPromises.push(supabase.from('inventory_items').insert(uploadedData.inventory_items));
    }
    
    if (uploadedData.stock_transactions && uploadedData.stock_transactions.length > 0) {
      insertPromises.push(supabase.from('stock_transactions').insert(uploadedData.stock_transactions));
    }
    
    if (uploadedData.transfers && uploadedData.transfers.length > 0) {
      insertPromises.push(supabase.from('transfers').insert(uploadedData.transfers));
    }

    const results = await Promise.all(insertPromises);
    
    // Check for errors
    const errors = results.filter(result => result.error);
    if (errors.length > 0) {
      console.error('Errors during data upload:', errors);
      return res.status(500).json({ error: 'Failed to upload some data' });
    }
    
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