// server.js - Enhanced API Key Management Server with Advanced License Controls
const express = require('express');
const morgan = require('morgan');
const crypto = require('crypto');
const dotenv = require('dotenv');
const path = require('path');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const fs = require('fs');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(cors());

// Serve static files from the public directory
app.use(express.static('public'));

// Create database directory if it doesn't exist
const dbDir = path.join(__dirname, 'database');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir);
}

// Enhanced device and license management
class DeviceLicenseManager {
  // Generate a complex device fingerprint
  static generateDeviceFingerprint(deviceData) {
    const fingerprintComponents = [
      deviceData.hardwareInfo || '',
      deviceData.cpuCores || '',
      deviceData.totalMemory || '',
      deviceData.osName || '',
      deviceData.osVersion || '',
      deviceData.browserName || '',
      deviceData.browserVersion || '',
      `${deviceData.screenWidth || ''}x${deviceData.screenHeight || ''}`,
      deviceData.timezone || '',
      deviceData.language || '',
      deviceData.userAgent || ''
    ];

    return crypto
      .createHash('sha512')
      .update(fingerprintComponents.join('|'))
      .digest('hex');
  }

  // Calculate fingerprint similarity
  static calculateFingerprintSimilarity(fingerprint1, fingerprint2) {
    let matches = 0;
    const shortStr = fingerprint1.length < fingerprint2.length ? fingerprint1 : fingerprint2;
    const longStr = fingerprint1.length < fingerprint2.length ? fingerprint2 : fingerprint1;

    for (let char of shortStr) {
      if (longStr.includes(char)) {
        matches++;
      }
    }

    return matches / Math.max(fingerprint1.length, fingerprint2.length);
  }

  static getWindowsUsername() {
    try {
      const os = require('os');
      const userInfo = os.userInfo();
      const username = userInfo.username;
      
      // Lấy đường dẫn home directory
      const homedir = os.homedir();
      const usernameFromPath = homedir.split('\\').filter(part => part)[1];
      
      return {
        username: username,
        usernameFromPath: usernameFromPath,
        homedir: homedir
      };
    } catch (error) {
      console.error('Error getting Windows username:', error);
      return {
        username: 'unknown',
        usernameFromPath: 'unknown',
        homedir: 'unknown'
      };
    }
  }

  // Extract comprehensive device information
  static extractDeviceData(req) {
    const userAgent = req.headers['user-agent'] || '';
    const deviceId = req.headers['device-id'] || 
                    req.headers['x-device-id'] || 
                    req.headers['x-fingerprint'] ||
                    this.generateBasicDeviceId(userAgent);
    
    const ipAddress = this.normalizeIpAddress(this.getClientIp(req));
    const windowsUser = this.getWindowsUsername();
    
    return {
      hardwareInfo: deviceId,
      cpuCores: this.detectCPUCores(userAgent),
      totalMemory: this.detectMemory(userAgent),
      osName: this.detectOperatingSystem(userAgent),
      osVersion: this.detectOSVersion(userAgent),
      browserName: this.detectBrowserName(userAgent),
      browserVersion: this.detectBrowserVersion(userAgent),
      screenWidth: req.headers['screen-width'] || '',
      screenHeight: req.headers['screen-height'] || '',
      timezone: req.headers['timezone'] || '',
      language: req.headers['accept-language'] || '',
      userAgent: userAgent,
      ipAddress: ipAddress,
      windowsUsername: windowsUser.username,  // Thêm thông tin username
      userHomedir: windowsUser.homedir       // Thêm đường dẫn home directory
    };
  }

  // Thêm phương thức mới để tạo deviceId cơ bản
  static generateBasicDeviceId(userAgent) {
    const browser = this.detectBrowserName(userAgent);
    const os = this.detectOperatingSystem(userAgent);
    const version = this.detectBrowserVersion(userAgent);
    return `${os}_${browser}_${version}_${Date.now()}`;
  }

  // Thêm phương thức chuẩn hóa địa chỉ IP
  static normalizeIpAddress(ip) {
    if (!ip) return '0.0.0.0';

    // Xử lý IPv6 localhost
    if (ip === '::1') return '127.0.0.1';
    
    // Xử lý IPv6 mapped IPv4
    if (ip.startsWith('::ffff:')) {
      return ip.substring(7);
    }
    
    // Nếu là IPv6, giữ nguyên format
    if (ip.includes(':')) {
      return ip;
    }
    
    return ip;
  }

  static detectVirtualization(networkInterfaces) {
    const virtualPatterns = [
      /^192\.168\.56\./,  // VirtualBox
      /^10\.0\.2\./,      // Standard NAT
      /^172\.16\./,       // Docker
      /^172\.17\./,       // Docker
      /vmware/i,          // VMware
      /virtual/i,         // Generic virtual
    ];

    return networkInterfaces.some(iface => 
      virtualPatterns.some(pattern => 
        pattern.test(iface.address) || pattern.test(iface.name)
      )
    );
  }

  static getNetworkInfo(req) {
    const os = require('os');
    const interfaces = os.networkInterfaces();
    const networkInfo = {
      primaryIPv4: null,
      primaryIPv6: null,
      virtualMachine: false,
      allIPs: []
    };

    // Collect all IPs
    Object.values(interfaces).forEach(iface => {
      iface.forEach(addr => {
        if (!addr.internal) { // Bỏ qua địa chỉ loopback
          const ipInfo = {
            address: addr.address,
            family: addr.family,
            isVirtual: this.isVirtualInterface(addr.address)
          };
          
          networkInfo.allIPs.push(ipInfo);

          // Set primary IPv4
          if (addr.family === 'IPv4' && !networkInfo.primaryIPv4) {
            networkInfo.primaryIPv4 = addr.address;
          }
          
          // Set primary IPv6
          if (addr.family === 'IPv6' && !networkInfo.primaryIPv6) {
            networkInfo.primaryIPv6 = addr.address;
          }
        }
      });
    });

    networkInfo.virtualMachine = networkInfo.allIPs.some(ip => ip.isVirtual);
    return networkInfo;
  }

  // Detect operating system
  static detectOperatingSystem(userAgent) {
    userAgent = userAgent.toLowerCase();
    if (userAgent.includes('windows')) return 'Windows';
    if (userAgent.includes('mac')) return 'MacOS';
    if (userAgent.includes('linux')) return 'Linux';
    if (userAgent.includes('android')) return 'Android';
    if (userAgent.includes('iphone') || userAgent.includes('ipad')) return 'iOS';
    return 'Unknown';
  }

  // Detect OS version
  static detectOSVersion(userAgent) {
    const osVersionMatch = userAgent.match(/\(([^)]+)\)/);
    return osVersionMatch ? osVersionMatch[1] : 'Unknown';
  }

  // Detect browser name
  static detectBrowserName(userAgent) {
    userAgent = userAgent.toLowerCase();
    if (userAgent.includes('chrome')) return 'Chrome';
    if (userAgent.includes('firefox')) return 'Firefox';
    if (userAgent.includes('safari')) return 'Safari';
    if (userAgent.includes('edge')) return 'Edge';
    if (userAgent.includes('opera')) return 'Opera';
    return 'Unknown';
  }

  // Detect browser version
  static detectBrowserVersion(userAgent) {
    const versionMatch = userAgent.match(/(?:Chrome|Firefox|Safari|Edge|Opera)\/(\d+\.\d+)/);
    return versionMatch ? versionMatch[1] : 'Unknown';
  }

  // Detect CPU cores (simulated)
  static detectCPUCores(userAgent) {
    // This is a simulation. In a real-world scenario, this would come from device capabilities
    return userAgent.includes('Windows') ? 4 : 
           userAgent.includes('Mac') ? 6 : 
           userAgent.includes('Linux') ? 2 : 0;
  }

  // Detect memory (simulated)
  static detectMemory(userAgent) {
    // This is a simulation. In a real-world scenario, this would come from device capabilities
    return userAgent.includes('Windows') ? 8 : 
           userAgent.includes('Mac') ? 16 : 
           userAgent.includes('Linux') ? 4 : 0;
  }

  // Get client IP (enhanced version)
  static getClientIp(req) {
    const forwardedFor = req.headers['x-forwarded-for'];
    let clientIp = null;

    if (forwardedFor) {
      const ips = forwardedFor.split(',').map(ip => ip.trim());
      // Lấy IP đầu tiên từ danh sách x-forwarded-for
      clientIp = ips[0];
    }

    // Nếu không có trong x-forwarded-for, thử các header khác
    if (!clientIp) {
      clientIp = req.headers['cf-connecting-ip'] || 
                req.headers['x-real-ip'] || 
                req.ip || 
                req.connection.remoteAddress;
    }

    // Chuẩn hóa IP
    clientIp = this.normalizeIpAddress(clientIp);
    
    // Nếu là localhost (127.0.0.1), sử dụng một IP local khác nếu có thể
    if (clientIp === '127.0.0.1' || clientIp === '::1') {
      // Lấy IP local thay vì localhost
      const networkInterfaces = require('os').networkInterfaces();
      
      // Ưu tiên các giao diện mạng không phải virtual
      for (const interfaceName in networkInterfaces) {
        for (const iface of networkInterfaces[interfaceName]) {
          // Chỉ lấy IPv4, bỏ qua internal và virtual interfaces
          if (iface.family === 'IPv4' && 
              !iface.internal && 
              !this.isVirtualInterface(iface.address)) {
            return iface.address;
          }
        }
      }
      
      // Nếu không tìm thấy IPv4 non-virtual, thử lấy bất kỳ IPv4 nào không phải internal
      for (const interfaceName in networkInterfaces) {
        for (const iface of networkInterfaces[interfaceName]) {
          if (iface.family === 'IPv4' && !iface.internal) {
            return iface.address;
          }
        }
      }
    }

    return clientIp || '0.0.0.0';
  }

  // Helper methods
  static isIPv4(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  }

  static isIPv6(ip) {
    return ip.includes(':');
  }

  static isVirtualInterface(ip) {
    const virtualPatterns = [
      /^192\.168\.56\./,  // VirtualBox
      /^10\.0\.2\./,      // Standard NAT
      /^172\.16\./,       // Docker
      /^172\.17\./,       // Docker
    ];
    return virtualPatterns.some(pattern => pattern.test(ip));
  }

  // Generate a secure license key
  static generateLicenseKey(name) {
    const timestamp = Date.now().toString();
    const randomPart = crypto.randomBytes(16).toString('hex');
    const namePart = name.replace(/\s+/g, '').toLowerCase();
    
    return crypto
      .createHash('sha256')
      .update(`${timestamp}|${randomPart}|${namePart}`)
      .digest('hex');
  }
}

// SQLite database connection
const dbPath = path.join(dbDir, 'apikeys.db');
let db;

// Initialize database and create tables if they don't exist
async function initializeDatabase() {
  db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  // Enable foreign keys
  await db.run('PRAGMA foreign_keys = ON');

  // Create tables with enhanced schema
  await db.exec(`
    CREATE TABLE IF NOT EXISTS apikeys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      isActive INTEGER DEFAULT 1,
      createdAt TEXT DEFAULT (datetime('now')),
      expiresAt TEXT,
      usageCount INTEGER DEFAULT 0,
      lastUsed TEXT,
      allowAutoRegister INTEGER DEFAULT 1,
      maxIpCount INTEGER DEFAULT 5,
      multipleDevicesPerIp INTEGER DEFAULT 0,
      usageLimit INTEGER DEFAULT 0,
      primaryDeviceFingerprint TEXT,
      licenseType TEXT DEFAULT 'permanent',
      deviceSimilarityThreshold REAL DEFAULT 0.8
    );
    
    CREATE TABLE IF NOT EXISTS allowed_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      apikey_id INTEGER NOT NULL,
      ip TEXT NOT NULL,
      createdAt TEXT DEFAULT (datetime('now')),
      lastUsed TEXT,
      deviceIdentifier TEXT,
      deviceFingerprint TEXT,
      deviceDetails TEXT,
      usageCount INTEGER DEFAULT 0, -- Thêm cột này để theo dõi số lần sử dụng cho mỗi IP
      UNIQUE(apikey_id, ip, deviceIdentifier),
      FOREIGN KEY (apikey_id) REFERENCES apikeys(id) ON DELETE CASCADE
    );
  `);
  
  console.log('Database initialized with enhanced schema');
}

// Middleware to verify API key and IP from header
  const verifyApiKey = async (req, res, next) => {
    const apiKey = req.headers["x-api-key"] || req.query.key;
    const deviceData = DeviceLicenseManager.extractDeviceData(req);
    const deviceFingerprint =
      DeviceLicenseManager.generateDeviceFingerprint(deviceData);
    const networkInfo = DeviceLicenseManager.getNetworkInfo(req);
    const normalizedIp = DeviceLicenseManager.normalizeIpAddress(
      deviceData.ipAddress
    );

    if (!apiKey) {
      return res.status(401).json({ error: "Cần có khóa API" });
    }

    try {
      // Get API key data
      const keyData = await db.get("SELECT * FROM apikeys WHERE key = ?", [
        apiKey,
      ]);

      if (!keyData) {
        return res.status(401).json({ error: "Invalid API key" });
      }

      if (!keyData.isActive) {
        return res.status(403).json({ error: "API key is inactive" });
      }

      if (keyData.expiresAt && new Date(keyData.expiresAt) < new Date()) {
        return res.status(403).json({ error: "API key has expired" });
      }

      // Check usage limit
      if (keyData.usageLimit > 0 && keyData.usageCount >= keyData.usageLimit) {
        return res.status(403).json({
          error: "Usage limit exceeded for this API key",
          usageLimit: keyData.usageLimit,
          currentUsage: keyData.usageCount,
        });
      }

      // Device similarity check for license verification
      let deviceSimilarity = 1; // Default full similarity for first device
      if (keyData.primaryDeviceFingerprint) {
        deviceSimilarity = DeviceLicenseManager.calculateFingerprintSimilarity(
          keyData.primaryDeviceFingerprint,
          deviceFingerprint
        );
      }

      // Threshold for device similarity (configurable per key)
      const similarityThreshold = keyData.deviceSimilarityThreshold || 0.8;

      // ===== PHẦN SỬA ĐỔI BẮT ĐẦU Ở ĐÂY =====
      
      // Kiểm tra IP đã tồn tại (bất kể thiết bị nào)
      const existingIP = await db.get(
        'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? LIMIT 1',
        [keyData.id, deviceData.ipAddress]
      );

      if (!existingIP) {
        // IP chưa tồn tại, kiểm tra giới hạn IP và đăng ký mới
        if (keyData.allowAutoRegister === 1) {
          // Đếm số lượng IP duy nhất đã đăng ký
          const uniqueIpCount = await db.get(
            "SELECT COUNT(DISTINCT ip) as count FROM allowed_ips WHERE apikey_id = ?",
            [keyData.id]
          );
          
          if (uniqueIpCount.count >= keyData.maxIpCount) {
            return res.status(403).json({
              error: "Maximum unique IP limit reached for this API key",
              maxIps: keyData.maxIpCount,
              currentUniqueIpCount: uniqueIpCount.count,
            });
          }
          
          // Nếu chưa có thiết bị chính, đặt thiết bị hiện tại làm thiết bị chính
          if (!keyData.primaryDeviceFingerprint) {
            await db.run(
              "UPDATE apikeys SET primaryDeviceFingerprint = ? WHERE id = ?",
              [deviceFingerprint, keyData.id]
            );
          }
          
          // Thêm IP mới với thông tin thiết bị
          await db.run(
            'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier, deviceFingerprint, deviceDetails, lastUsed) VALUES (?, ?, ?, ?, ?, datetime("now"))',
            [
              keyData.id,
              deviceData.ipAddress,
              deviceData.hardwareInfo || "",
              deviceFingerprint,
              JSON.stringify(deviceData),
            ]
          );
          console.log(
            `Auto-added IP ${deviceData.ipAddress} with device ${deviceData.hardwareInfo} for key ${apiKey}`
          );
        } else {
          return res.status(403).json({
            error:
              "IP not authorized for this API key and auto-registration is disabled",
            clientIP: deviceData.ipAddress,
            deviceIdentifier: deviceData.hardwareInfo,
          });
        }
      } else {
        // IP đã tồn tại, thực hiện kiểm tra thiết bị chặt chẽ hơn
        if (existingIP) {
          // Lấy thông tin thiết bị đã đăng ký
          const registeredDevice = await db.get(
            'SELECT deviceFingerprint, deviceDetails FROM allowed_ips WHERE id = ?',
            [existingIP.id]
          );
          
          // Tính toán mức độ tương đồng thiết bị hiện tại với thiết bị đã đăng ký
          const deviceMatch = DeviceLicenseManager.calculateFingerprintSimilarity(
            registeredDevice.deviceFingerprint,
            deviceFingerprint
          );
          
          // Kiểm tra thiết bị có phải là thiết bị đã đăng ký không
          if (deviceMatch < 0.95) { // Thiết lập ngưỡng rất cao
            return res.status(403).json({
              error: "Device verification failed. This API key is restricted to the originally registered device.",
              deviceSimilarity: deviceMatch,
              requiredSimilarity: 0.95
            });
          }
          
          // Thêm kiểm tra thông tin chi tiết như tên người dùng, đường dẫn thư mục
          const registeredDetails = JSON.parse(registeredDevice.deviceDetails);
          if (registeredDetails.windowsUsername !== deviceData.windowsUsername || 
              registeredDetails.userHomedir !== deviceData.userHomedir) {
            return res.status(403).json({
              error: "User account verification failed. Access restricted to the original user account.",
            });
          }
        }
        
        // Cập nhật thời gian sử dụng cuối
        await db.run(
          'UPDATE allowed_ips SET lastUsed = datetime("now") WHERE id = ?',
          [existingIP.id]
        );
      }
      
      // ===== PHẦN SỬA ĐỔI KẾT THÚC Ở ĐÂY =====

      // Check device similarity for stricter control
      if (deviceSimilarity < similarityThreshold) {
        return res.status(403).json({
          error: "Device verification failed",
          deviceSimilarity: deviceSimilarity,
          similarityThreshold: similarityThreshold,
        });
      }

      // Update usage statistics for the API key
      await db.run(
        'UPDATE apikeys SET usageCount = usageCount + 1, lastUsed = datetime("now") WHERE id = ?',
        [keyData.id]
      );

      // ===== SỬA ĐỔI CÁC PHẦN LIÊN QUAN ĐẾN ALLOWED IPs =====
      
      // Lấy danh sách IP duy nhất
      const allowedIPs = await db.all(
        "SELECT ip, deviceIdentifier, deviceFingerprint FROM allowed_ips WHERE apikey_id = ? GROUP BY ip",
        [keyData.id]
      );

      // Gắn dữ liệu vào request
      req.apiKeyData = {
        ...keyData,
        allowedIPs: allowedIPs.map((item) => ({
          ip: item.ip,
          deviceIdentifier: item.deviceIdentifier,
          deviceFingerprint: item.deviceFingerprint,
        })),
        currentDeviceData: deviceData,
        deviceSimilarity: deviceSimilarity,
      };

      next();
    } catch (error) {
      console.error('API key verification error:', error);
      return res.status(500).json({ 
        error: 'Internal server error',
        details: error.message 
      });
    }
  };

// Admin routes for managing API keys with enhanced features
const adminRouter = express.Router();

// Create a new API key with advanced configurations
adminRouter.post('/keys', async (req, res) => {
  try {
    const { 
      name, 
      allowedIPs, 
      expiresAt, 
      allowAutoRegister, 
      maxIpCount, 
      multipleDevicesPerIp, 
      usageLimit,
      licenseType,
      deviceSimilarityThreshold
    } = req.body;
    
    if (!name) {
      return res.status(400).json({ error: 'Name is required' });
    }
    
    const key = DeviceLicenseManager.generateLicenseKey(name);
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Insert the new API key with enhanced configurations
    const result = await db.run(
      `INSERT INTO apikeys (
        key, name, expiresAt, allowAutoRegister, maxIpCount, 
        multipleDevicesPerIp, usageLimit, licenseType, deviceSimilarityThreshold
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        key,
        name, 
        expiresAt, 
        allowAutoRegister === false ? 0 : 1,
        maxIpCount || 5,
        multipleDevicesPerIp === true ? 1 : 0,
        usageLimit || 0,
        licenseType || 'permanent',
        deviceSimilarityThreshold || 0.8
      ]
    );
    
    const keyId = result.lastID;
    
    // Insert allowed IPs
    if (allowedIPs && allowedIPs.length > 0) {
      const insertIpStatement = await db.prepare(
        'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)'
      );
      
      for (const ip of allowedIPs) {
        await insertIpStatement.run(keyId, ip);
      }
      
      await insertIpStatement.finalize();
    }
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Get the created API key with IPs
    const newKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all('SELECT ip, deviceIdentifier, deviceFingerprint FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    res.status(201).json({
      ...newKey,
      allowedIPs: ips.map(item => item.ip),
      ipDetails: ips
    });
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error creating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all API keys with comprehensive details
adminRouter.get('/keys', async (req, res) => {
  try {
    const keys = await db.all('SELECT * FROM apikeys ORDER BY createdAt DESC');
    
    // Get allowed IPs and device details for each key
    for (const key of keys) {
      const ips = await db.all(
        'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
        [key.id]
      );
      
      // Parse device details if possible
      key.ipDetails = ips.map(ip => ({
        ...ip,
        parsedDeviceDetails: ip.deviceDetails ? JSON.parse(ip.deviceDetails) : null
      }));
      
      key.allowedIPs = ips.map(item => item.ip);
    }
    
    res.json(keys);
  } catch (error) {
    console.error('Error fetching API keys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a single API key with detailed information
adminRouter.get('/keys/:id', async (req, res) => {
  try {
    const key = await db.get('SELECT * FROM apikeys WHERE id = ?', [req.params.id]);
    
    if (!key) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    const ips = await db.all(
      'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
      [key.id]
    );
    
    // Parse device details if possible
    key.ipDetails = ips.map(ip => ({
      ...ip,
      parsedDeviceDetails: ip.deviceDetails ? JSON.parse(ip.deviceDetails) : null
    }));
    
    // Lấy danh sách IP duy nhất
    const uniqueIps = [...new Set(ips.map(item => item.ip))];
    key.allowedIPs = uniqueIps;
    key.uniqueIpCount = uniqueIps.length;
    
    res.json(key);
  } catch (error) {
    console.error('Error fetching API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update an API key with advanced configurations
adminRouter.put('/keys/:id', async (req, res) => {
  try {
    const { 
      name, 
      allowedIPs, 
      isActive, 
      expiresAt, 
      allowAutoRegister, 
      maxIpCount, 
      multipleDevicesPerIp, 
      usageLimit,
      licenseType,
      deviceSimilarityThreshold
    } = req.body;
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Update the API key
    await db.run(
      `UPDATE apikeys 
       SET name = ?, 
           isActive = ?, 
           expiresAt = ?, 
           allowAutoRegister = ?, 
           maxIpCount = ?, 
           multipleDevicesPerIp = ?, 
           usageLimit = ?,
           licenseType = ?,
           deviceSimilarityThreshold = ?
       WHERE id = ?`,
      [
        name || existingKey.name,
        isActive !== undefined ? isActive : existingKey.isActive,
        expiresAt || existingKey.expiresAt,
        allowAutoRegister !== undefined ? (allowAutoRegister ? 1 : 0) : existingKey.allowAutoRegister,
        maxIpCount || existingKey.maxIpCount,
        multipleDevicesPerIp !== undefined ? (multipleDevicesPerIp ? 1 : 0) : existingKey.multipleDevicesPerIp,
        usageLimit !== undefined ? usageLimit : existingKey.usageLimit,
        licenseType || existingKey.licenseType,
        deviceSimilarityThreshold !== undefined ? deviceSimilarityThreshold : existingKey.deviceSimilarityThreshold,
        keyId
      ]
    );
    
    // Update allowed IPs if provided
    if (allowedIPs) {
      // Delete existing IPs
      await db.run('DELETE FROM allowed_ips WHERE apikey_id = ?', [keyId]);
      
      // Insert new IPs
      if (allowedIPs.length > 0) {
        const insertIpStatement = await db.prepare(
          'INSERT INTO allowed_ips (apikey_id, ip) VALUES (?, ?)'
        );
        
        for (const ip of allowedIPs) {
          await insertIpStatement.run(keyId, ip);
        }
        
        await insertIpStatement.finalize();
      }
    }
    
    // Commit the transaction
    await db.run('COMMIT');
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all(
      'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
      [keyId]
    );
    
    // Parse device details if possible
    updatedKey.ipDetails = ips.map(ip => ({
      ...ip,
      parsedDeviceDetails: ip.deviceDetails ? JSON.parse(ip.deviceDetails) : null
    }));
    
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
    res.json(updatedKey);
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error updating API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset usage count for an API key
adminRouter.post('/keys/:id/reset-usage', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Reset usage count
    await db.run('UPDATE apikeys SET usageCount = 0 WHERE id = ?', [keyId]);
    
    // Get the updated API key
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all(
      'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
      [keyId]
    );
    
    // Parse device details if possible
    updatedKey.ipDetails = ips.map(ip => ({
      ...ip,
      parsedDeviceDetails: ip.deviceDetails ? JSON.parse(ip.deviceDetails) : null
    }));
    
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error resetting usage count:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete an API key
adminRouter.delete('/keys/:id', async (req, res) => {
  try {
    const keyId = req.params.id;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the key (cascades to allowed_ips due to foreign key constraint)
    await db.run('DELETE FROM apikeys WHERE id = ?', [keyId]);
    
    res.status(204).end();
  } catch (error) {
    console.error('Error deleting API key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register IP for an existing API key with device details
adminRouter.post('/keys/:id/ip', async (req, res) => {
  try {
    const { ip, deviceIdentifier, deviceDetails } = req.body;
    const keyId = req.params.id;
    
    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Check if we're under the IP limit
    const ipCount = await db.get('SELECT COUNT(*) as count FROM allowed_ips WHERE apikey_id = ?', [keyId]);
    
    if (ipCount.count >= existingKey.maxIpCount) {
      return res.status(403).json({ 
        error: 'Maximum IP limit reached for this API key',
        maxIps: existingKey.maxIpCount,
        currentIpCount: ipCount.count
      });
    }
    
    // Generate device fingerprint if device details are provided
    const deviceFingerprint = deviceDetails 
      ? DeviceLicenseManager.generateDeviceFingerprint(deviceDetails) 
      : null;
    
    // Prepare device details for storage
    const formattedDeviceDetails = deviceDetails 
      ? JSON.stringify(deviceDetails) 
      : null;
    
    // Check if IP already exists
    const existingIp = await db.get(
      'SELECT * FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND (deviceIdentifier = ? OR ? IS NULL)', 
      [keyId, ip, deviceIdentifier, deviceIdentifier]
    );
    
    if (!existingIp) {
      // Add new IP with device identifier and details
      await db.run(
        'INSERT INTO allowed_ips (apikey_id, ip, deviceIdentifier, deviceFingerprint, deviceDetails) VALUES (?, ?, ?, ?, ?)',
        [keyId, ip, deviceIdentifier || null, deviceFingerprint, formattedDeviceDetails]
      );
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all(
      'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
      [keyId]
    );
    
    // Parse device details if possible
    updatedKey.ipDetails = ips.map(ipItem => ({
      ...ipItem,
      parsedDeviceDetails: ipItem.deviceDetails ? JSON.parse(ipItem.deviceDetails) : null
    }));
    
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error registering IP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove IP from an API key
adminRouter.delete('/keys/:id/ip/:ip', async (req, res) => {
  try {
    const keyId = req.params.id;
    const ip = req.params.ip;
    const deviceIdentifier = req.query.deviceIdentifier;
    
    // Check if key exists
    const existingKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    
    if (!existingKey) {
      return res.status(404).json({ error: 'API key not found' });
    }
    
    // Delete the IP - if deviceIdentifier is provided, only delete for that device
    let result;
    if (deviceIdentifier) {
      result = await db.run(
        'DELETE FROM allowed_ips WHERE apikey_id = ? AND ip = ? AND deviceIdentifier = ?',
        [keyId, ip, deviceIdentifier]
      );
    } else {
      result = await db.run(
        'DELETE FROM allowed_ips WHERE apikey_id = ? AND ip = ?',
        [keyId, ip]
      );
    }
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'IP not found for this API key' });
    }
    
    // Get updated key with IPs
    const updatedKey = await db.get('SELECT * FROM apikeys WHERE id = ?', [keyId]);
    const ips = await db.all(
      'SELECT ip, deviceIdentifier, deviceFingerprint, deviceDetails, createdAt, lastUsed FROM allowed_ips WHERE apikey_id = ?', 
      [keyId]
    );
    
    // Parse device details if possible
    updatedKey.ipDetails = ips.map(ipItem => ({
      ...ipItem,
      parsedDeviceDetails: ipItem.deviceDetails ? JSON.parse(ipItem.deviceDetails) : null
    }));
    
    updatedKey.allowedIPs = ips.map(item => item.ip);
    
    res.json(updatedKey);
  } catch (error) {
    console.error('Error removing IP:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Rate limiter for API endpoints
const apiRateLimiter = new Map();
const tempKeyRateLimiter = new Map(); // Rate limiter riêng cho generate-temp-key

// Middleware to limit API request rates
function rateLimiterMiddleware(req, res, next) {
  const clientIP = DeviceLicenseManager.getClientIp(req);
  const now = Date.now();
  
  if (apiRateLimiter.has(clientIP)) {
    const requests = apiRateLimiter.get(clientIP);
    
    // Remove requests older than 1 minute
    const recentRequests = requests.filter(time => now - time < 60000);
    
    // Add current request
    recentRequests.push(now);
    apiRateLimiter.set(clientIP, recentRequests);
    
    // Tăng giới hạn lên 100 request mỗi phút
    if (recentRequests.length > 100) {
      return res.status(429).json({ 
        error: 'Too many requests. Please try again later.',
        retryAfter: 60 // seconds
      });
    }
  } else {
    // First time request from this IP
    apiRateLimiter.set(clientIP, [now]);
  }
  
  next();
}

// Middleware riêng cho generate-temp-key với giới hạn thấp hơn
function tempKeyRateLimiterMiddleware(req, res, next) {
  const clientIP = DeviceLicenseManager.getClientIp(req);
  const now = Date.now();
  
  if (tempKeyRateLimiter.has(clientIP)) {
    const requests = tempKeyRateLimiter.get(clientIP);
    
    // Remove requests older than 1 minute
    const recentRequests = requests.filter(time => now - time < 60000);
    
    // Add current request
    recentRequests.push(now);
    tempKeyRateLimiter.set(clientIP, recentRequests);
    
    // Giới hạn 3 request mỗi phút cho generate-temp-key
    if (recentRequests.length > 3) {
      return res.status(429).json({ 
        error: 'Too many temporary key requests. Please try again later.',
        retryAfter: 60 // seconds
      });
    }
  } else {
    // First time request from this IP
    tempKeyRateLimiter.set(clientIP, [now]);
  }
  
  next();
}

// Periodic cleanup của cả hai rate limiter
setInterval(() => {
  const now = Date.now();
  
  // Cleanup apiRateLimiter
  for (const [ip, times] of apiRateLimiter.entries()) {
    const recentRequests = times.filter(time => now - time < 600000); // 10 minutes
    
    if (recentRequests.length === 0) {
      apiRateLimiter.delete(ip);
    } else {
      apiRateLimiter.set(ip, recentRequests);
    }
  }
  
  // Cleanup tempKeyRateLimiter
  for (const [ip, times] of tempKeyRateLimiter.entries()) {
    const recentRequests = times.filter(time => now - time < 600000); // 10 minutes
    
    if (recentRequests.length === 0) {
      tempKeyRateLimiter.delete(ip);
    } else {
      tempKeyRateLimiter.set(ip, recentRequests);
    }
  }
}, 300000); // Run every 5 minutes

// Apply rate limiting to sensitive routes
app.use('/admin', rateLimiterMiddleware);
// app.use('/api', rateLimiterMiddleware); // Đã comment
app.use('/verify', rateLimiterMiddleware);

// Áp dụng middleware riêng cho generate-temp-key
app.get('/generate-temp-key', tempKeyRateLimiterMiddleware, async (req, res) => {
  const clientIP = DeviceLicenseManager.getClientIp(req);
  const deviceData = DeviceLicenseManager.extractDeviceData(req);
  const now = new Date();
  
  try {
    // Create a temporary license with strict limitations
    const tempKey = DeviceLicenseManager.generateLicenseKey('TempKey_' + clientIP.replace(/\./g, '_'));
    
    // Start a transaction
    await db.run('BEGIN TRANSACTION');
    
    // Calculate expiration (30 minutes from now)
    const expirationTime = new Date(now.getTime() + 1800000);
    
    // Insert temporary key
    const result = await db.run(
      `INSERT INTO apikeys (
        key, name, expiresAt, allowAutoRegister, maxIpCount, 
        multipleDevicesPerIp, usageLimit, licenseType, 
        primaryDeviceFingerprint, deviceSimilarityThreshold
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        tempKey,
        `TempKey_${clientIP}`,
        expirationTime.toISOString(),
        0, // Disable auto-register
        1, // Max 1 IP
        0, // No multiple devices per IP
        5, // 5 usage limit
        'temporary', // License type
        DeviceLicenseManager.generateDeviceFingerprint(deviceData), // Primary device fingerprint
        0.9 // Strict device similarity
      ]
    );
    
    const keyId = result.lastID;
    
    // Register the client IP
    await db.run(
      `INSERT INTO allowed_ips (
        apikey_id, ip, deviceIdentifier, deviceFingerprint, 
        deviceDetails, lastUsed
      ) VALUES (?, ?, ?, ?, ?, datetime('now'))`,
      [
        keyId,
        clientIP,
        deviceData.hardwareInfo || '',
        DeviceLicenseManager.generateDeviceFingerprint(deviceData),
        JSON.stringify(deviceData)
      ]
    );
    
    // Commit transaction
    await db.run('COMMIT');
    
    // Prepare response
    res.json({
      success: true,
      apiKey: tempKey,
      expiresAt: expirationTime.toISOString(),
      usageLimit: 5,
      registeredIP: clientIP,
      deviceDetails: {
        os: deviceData.osName,
        browser: deviceData.browserName,
        deviceIdentifier: deviceData.hardwareInfo
      },
      testEndpoint: `/api/data?key=${tempKey}`
    });
  } catch (error) {
    await db.run('ROLLBACK');
    console.error('Error generating temporary key:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Register admin routes
app.use('/admin', adminRouter);

// API routes that require API key authentication
const apiRouter = express.Router();
apiRouter.use(verifyApiKey);

// Sample protected API endpoint with enhanced details
// Sample protected API endpoint with enhanced details
apiRouter.get('/data-url', (req, res) => {
  const networkInfo = DeviceLicenseManager.getNetworkInfo(req);
  
  res.json({ 
    message: 'You have access to protected data',
    keyDetails: {
      name: req.apiKeyData.name,
      type: req.apiKeyData.licenseType,
      usageCount: req.apiKeyData.usageCount,
      usageLimit: req.apiKeyData.usageLimit,
      remainingUsage: req.apiKeyData.usageLimit > 0 
        ? req.apiKeyData.usageLimit - req.apiKeyData.usageCount 
        : 'Unlimited'
    },
    deviceInfo: {
        clientIP: req.apiKeyData.currentDeviceData.ipAddress,
        networkInfo: {
          primaryIPv4: networkInfo.primaryIPv4,
          primaryIPv6: networkInfo.primaryIPv6,
          allIPs: networkInfo.allIPs
        },
        // Đã thay đổi từ deviceIdentifier đầy đủ sang chỉ hiển thị hệ điều hành
        deviceIdentifier: req.apiKeyData.currentDeviceData.osName,
        os: req.apiKeyData.currentDeviceData.osName,
        // Đã bỏ trường browser
        deviceSimilarity: req.apiKeyData.deviceSimilarity,
        // Đã đơn giản hóa thông tin user
        user: req.apiKeyData.currentDeviceData.windowsUsername || 'unknown'
      },
      allowedIPs: req.apiKeyData.allowedIPs.map(item => ({
        ip: item.ip,
        // Rút gọn deviceIdentifier chỉ hiển thị hệ điều hành
        deviceIdentifier: item.deviceIdentifier ? item.deviceIdentifier.split('_')[0] : '',
        // Vẫn giữ fingerprint vì nó quan trọng cho bảo mật
        deviceFingerprint: item.deviceFingerprint
      }))
    });
});

// URL-based API verification endpoint
app.get('/verify', verifyApiKey, (req, res) => {
  res.json({ 
    valid: true,
    message: 'API key is valid',
    keyDetails: {
      name: req.apiKeyData.name,
      type: req.apiKeyData.licenseType,
      expiresAt: req.apiKeyData.expiresAt,
      usageCount: req.apiKeyData.usageCount,
      usageLimit: req.apiKeyData.usageLimit
    },
    deviceInfo: {
      clientIP: req.apiKeyData.currentDeviceData.ipAddress,
      deviceIdentifier: req.apiKeyData.currentDeviceData.hardwareInfo,
      deviceSimilarity: req.apiKeyData.deviceSimilarity
    }
  });
});

// Register API routes
app.use('/api', apiRouter);

// Serve the main HTML file for any unhandled routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

let server;

// Khởi tạo server sau khi database đã sẵn sàng
initializeDatabase()
  .then(() => {
    server = app.listen(PORT, HOST, () => {
      console.log(`Server running on ${HOST}:${PORT}`);
      console.log('Environment:', process.env.NODE_ENV || 'development');
      console.log('Database Path:', dbPath);
    });
  })
  .catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });

// Xử lý shutdown gracefully
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  try {
    if (db) {
      await db.close();
      console.log('Database connection closed');
    }
    if (server) {
      server.close(() => {
        console.log('HTTP server closed');
        process.exit(0);
      });
    } else {
      process.exit(0); 
    }
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
});

// Export key components for potential use in other modules
module.exports = {
  app,
  DeviceLicenseManager,
  verifyApiKey,
  db
};
