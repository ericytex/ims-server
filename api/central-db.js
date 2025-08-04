import fs from 'fs';
import path from 'path';
import sqlite3 from 'sqlite3';

const CENTRAL_DB_PATH = path.join(process.cwd(), 'data', 'central_ims.db');

// Ensure data directory exists
const dataDir = path.dirname(CENTRAL_DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize central database
function initCentralDb() {
  if (!fs.existsSync(CENTRAL_DB_PATH)) {
    const db = new sqlite3.Database(CENTRAL_DB_PATH);
    
    // Create schema
    db.serialize(() => {
      // Users table
      db.run(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        role TEXT NOT NULL CHECK (role IN ('admin', 'regional_manager', 'district_manager', 'facility_manager', 'inventory_worker')),
        facility_id TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`);

      // Facilities table
      db.run(`CREATE TABLE IF NOT EXISTS facilities (
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
      )`);

      // Inventory items table
      db.run(`CREATE TABLE IF NOT EXISTS inventory_items (
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
      )`);

      // Stock transactions table
      db.run(`CREATE TABLE IF NOT EXISTS stock_transactions (
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
      )`);

      // Transfers table
      db.run(`CREATE TABLE IF NOT EXISTS transfers (
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
      )`);

      // Notifications table
      db.run(`CREATE TABLE IF NOT EXISTS notifications (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('stock_alert', 'transfer_update', 'system_notification')),
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        read BOOLEAN DEFAULT FALSE,
        created_at TEXT NOT NULL,
        data TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )`);

      // Insert some initial data
      db.run(`INSERT OR IGNORE INTO users (id, name, email, phone, role, created_at, updated_at) 
               VALUES ('admin-1', 'Admin User', 'admin@ims.com', '+256700000000', 'admin', 
                       datetime('now'), datetime('now'))`);
      
      db.run(`INSERT OR IGNORE INTO facilities (id, name, type, region, district, address, 
               contact_person, contact_phone, created_at, updated_at) 
               VALUES ('facility-1', 'Main Warehouse', 'warehouse', 'Central', 'Kampala', 
                       'Kampala, Uganda', 'John Doe', '+256700000001', datetime('now'), datetime('now'))`);
      
      db.run(`INSERT OR IGNORE INTO inventory_items (id, name, description, category, sku, unit, 
               current_stock, min_stock, max_stock, cost, supplier, facility_id, location, 
               created_at, updated_at, status) 
               VALUES ('item-1', 'Paracetamol 500mg', 'Pain relief medication', 'Drugs', 'PAR001', 
                       'Packs', 500, 50, 1000, 5000.00, 'Pharma Ltd', 'facility-1', 'Shelf A1', 
                       datetime('now'), datetime('now'), 'active')`);
    });

    db.close();
    console.log('✅ Central database initialized');
  }
}

// Initialize on module load
initCentralDb();

export default function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Verify authentication
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const token = authHeader.substring(7);
  // Add your token verification logic here
  // For now, we'll accept any token

  if (req.method === 'GET' && req.url.includes('/download')) {
    // Download central database
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
  } else if (req.method === 'POST' && req.url.includes('/upload')) {
    // Upload database from client
    try {
      // For Vercel, we need to handle the request body differently
      let dbBuffer;
      
      if (req.body && req.body.database) {
        // If the body is already parsed
        dbBuffer = Buffer.from(req.body.database);
      } else {
        // Handle raw body
        dbBuffer = Buffer.from(req.body);
      }
      
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
  } else {
    res.status(404).json({ error: 'Endpoint not found' });
  }
} 