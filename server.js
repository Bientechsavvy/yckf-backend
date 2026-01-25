// ============================================
// YCKF BACKEND SERVER - PRODUCTION READY
// File: server.js
// WITH AUTO-EMAIL FUNCTIONALITY
// ============================================

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { Pool } = require('pg'); // ⭐ NEW LINE
require('dotenv').config();

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

//Test connection
pool.on('connect', () => {
  console.log('✅ PostgreSQL connected');
});

pool.on('error', (err) => {
  console.error('❌ Database error:', err);
});

// ============================================
// TRUST PROXY (Required for Render/Cloud deployment)
// ============================================
app.set('trust proxy', 1); // Trust first proxy (Render's load balancer)

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(cors());



// ============================================
// CONFIGURATION
// ============================================
const JWT_SECRET = process.env.JWT_SECRET || '5e83a80b862d52fdd6716a689c38d7b534e930baefc33057a6472722daded295';
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';


// ============================================
// EMAIL CONFIGURATION
// ============================================
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

// Debug logging - CRITICAL for Railway deployment
console.log('\n📧 ============================================');
console.log('📧 EMAIL CONFIGURATION CHECK');
console.log('📧 ============================================');
console.log(`📧 EMAIL_USER exists: ${EMAIL_USER ? 'YES ✓' : 'NO ✗'}`);
console.log(`📧 EMAIL_PASS exists: ${EMAIL_PASS ? 'YES ✓' : 'NO ✗'}`);
if (EMAIL_USER) console.log(`📧 EMAIL_USER value: ${EMAIL_USER}`);
if (EMAIL_PASS) console.log(`📧 EMAIL_PASS length: ${EMAIL_PASS.length} chars`);
console.log('📧 ============================================\n');

// Official YCKF Email Addresses
const ADMIN_EMAIL = 'yckfadmin@youngcyberknightsfoundation.org';
const BACKUP_EMAIL = 'brightpeterkwakuboateng@gmail.com';

// ============================================
// EMAIL TRANSPORTER SETUP
// ============================================
let emailTransporter = null;

if (EMAIL_USER && EMAIL_PASS) {
  console.log('📧 Creating email transporter...');

  try {
    emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
      },
      tls: {
        rejectUnauthorized: false
      },
      connectionTimeout: 10000,
      socketTimeout: 10000,
      debug: true, // Enable debug output
      logger: true  // Enable logger
    });

    console.log('📧 Email transporter created, verifying connection...');

    // Verify connection
    emailTransporter.verify((error, success) => {
      if (error) {
        console.log('\n❌ ============================================');
        console.log('❌ GMAIL SMTP CONNECTION FAILED');
        console.log('❌ ============================================');
        console.log('❌ Error:', error.message);
        console.log('❌ Error code:', error.code);
        console.log('❌ Error command:', error.command);
        console.log('\n⚠️  TROUBLESHOOTING STEPS:');
        console.log('   1. Verify EMAIL_USER is correct Gmail address');
        console.log('   2. Verify EMAIL_PASS is 16-char App Password (NOT regular password)');
        console.log('   3. Generate App Password: https://myaccount.google.com/apppasswords');
        console.log('   4. Ensure 2FA is enabled on Gmail account');
        console.log('   5. Check for spaces in App Password (remove them)');
        console.log('   6. Try regenerating a new App Password');
        console.log('❌ ============================================\n');
      } else {
        console.log('\n✅ ============================================');
        console.log('✅ EMAIL SERVICE CONNECTED SUCCESSFULLY');
        console.log('✅ ============================================');
        console.log(`✅ Sending from: ${EMAIL_USER}`);
        console.log(`✅ Ready to send emails to: ${ADMIN_EMAIL}`);
        console.log('✅ ============================================\n');
      }
    });
  } catch (error) {
    console.log('\n❌ ============================================');
    console.log('❌ FAILED TO CREATE EMAIL TRANSPORTER');
    console.log('❌ ============================================');
    console.log('❌ Error:', error.message);
    console.log('❌ ============================================\n');
  }
} else {
  console.log('\n⚠️  ============================================');
  console.log('⚠️  EMAIL SERVICE NOT CONFIGURED');
  console.log('⚠️  ============================================');
  console.log('⚠️  Missing environment variables:');
  if (!EMAIL_USER) console.log('   ✗ EMAIL_USER is not set');
  if (!EMAIL_PASS) console.log('   ✗ EMAIL_PASS is not set');
  console.log('\n⚠️  TO FIX:');
  console.log('   1. Go to Railway project settings');
  console.log('   2. Click "Variables" tab');
  console.log('   3. Add EMAIL_USER = your_gmail@gmail.com');
  console.log('   4. Add EMAIL_PASS = your_16_char_app_password');
  console.log('   5. Redeploy the service');
  console.log('⚠️  ============================================\n');
}

// ============================================
// DATABASE INITIALIZATION
// ============================================
async function initializeDatabase() {
  try {
    console.log('🔄 Initializing database...');

    // Create users table with UNIQUE email constraint
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create index on email for faster lookups
    await pool.query(`
      CREATE INDEX IF NOT EXISTS idx_users_email_lower ON users(LOWER(email))
    `);

    // Create subscriptions table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id VARCHAR(255) PRIMARY KEY,
        user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
        is_active BOOLEAN DEFAULT true,
        activated_at TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        payment_reference VARCHAR(255),
        payment_method VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create coupons table
 // Create coupons table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS coupons (
        id VARCHAR(255) PRIMARY KEY,
        code VARCHAR(100) UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT true,
        description TEXT,
        duration_type VARCHAR(20) NOT NULL DEFAULT '24h',
        expires_at TIMESTAMP,
        max_redemptions INTEGER,
        current_redemptions INTEGER DEFAULT 0,
        created_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ⭐ NEW: Add migration to update existing table
    // This adds the duration_type column if it doesn't exist
    try {
      await pool.query(`
        ALTER TABLE coupons 
        ADD COLUMN IF NOT EXISTS duration_type VARCHAR(20) DEFAULT '24h'
      `);
      console.log('✅ Coupons table migrated - duration_type column added');
    } catch (migrationError) {
      // Column might already exist, that's OK
      console.log('ℹ️  Coupons table migration: column already exists or migration not needed');
    }

    // Create reset_codes table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reset_codes (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        code VARCHAR(10) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create audit_logs table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        action VARCHAR(255) NOT NULL,
        performed_by VARCHAR(255),
        target_user VARCHAR(255),
        details JSONB
      )
    `);
    console.log('✅ Database tables created');

    // Inside initializeDatabase() function, after creating users table

    // Create coupon_redemptions table
    await pool.query(`
  CREATE TABLE IF NOT EXISTS coupon_redemptions (
    id VARCHAR(255) PRIMARY KEY,
    coupon_code VARCHAR(100) NOT NULL,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
    redeemed_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    access_duration INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);

    // Create demo_sessions table
    await pool.query(`
  CREATE TABLE IF NOT EXISTS demo_sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    device_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`);
    console.log('✅ Coupon redemptions and demo sessions tables ready');

    // Create default admin if doesn't exist
    const adminCheck = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      ['admin@yckf.org']
    );

    if (adminCheck.rows.length === 0) {
      const adminHash = await bcrypt.hash('SecureAdmin@2024', 10);
      await pool.query(
        'INSERT INTO users (id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5)',
        [uuidv4(), 'admin@yckf.org', 'YCKF Admin', adminHash, 'admin']
      );
      console.log('✅ Default admin created');
    }

  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    throw error;
  }
}
let currentDemoToken = bcrypt.hashSync('DEMO-YCKF-2024', 10);

// ============================================
// RATE LIMITING
// ============================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, please try again later' }
});

const couponLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many coupon attempts, please slow down' }
});

const resetPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Too many password reset attempts, please try again later' }
});

const emailLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: { error: 'Too many email requests, please slow down' }
});

// ============================================
// MIDDLEWARE
// ============================================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    logAudit('UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT', req.user.id, null, {
      endpoint: req.path
    });
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================
// AUDIT LOGGING
// ============================================
async function logAudit(action, performedBy, targetUser, details) {
  try {
    await pool.query(
      'INSERT INTO audit_logs (action, performed_by, target_user, details) VALUES ($1, $2, $3, $4)',
      [action, performedBy, targetUser, JSON.stringify(details)]
    );
    console.log(`[AUDIT] ${action} by ${performedBy}`, details);
  } catch (error) {
    console.error('Audit log failed:', error);
  }
}

// ============================================
// EMAIL HELPER FUNCTIONS
// ============================================
function generateResetCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendResetCodeEmail(email, code, userName) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const mailOptions = {
    from: `"YCKF App" <${EMAIL_USER}>`,
    to: email,
    subject: 'Password Reset Code - YCKF',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #0066cc; color: white; padding: 20px; text-align: center; }
          .content { background: #f9f9f9; padding: 30px; }
          .code-box { background: white; border: 2px dashed #0066cc; padding: 20px; text-align: center; margin: 20px 0; }
          .code { font-size: 32px; font-weight: bold; color: #0066cc; letter-spacing: 5px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>��� Password Reset Request</h1>
          </div>
          <div class="content">
            <p>Hello ${userName || 'User'},</p>
            <p>We received a request to reset your password for your YCKF account.</p>
            <p>Your password reset code is:</p>
            <div class="code-box">
              <div class="code">${code}</div>
            </div>
            <p><strong>This code will expire in 15 minutes.</strong></p>
            <p>If you didn't request this, please ignore this email.</p>
          </div>
        </div>
      </body>
      </html>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}

// ==========================START=============================
// ============================================
// AUTO-EMAIL: ACCOUNT CREATION CONFIRMATION
// ============================================
async function sendAccountCreationEmail(userData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const mailOptions = {
    from: `"YCKF App" <${EMAIL_USER}>`,
    to: userData.email,
    subject: '🎉 Welcome to YCKF - Account Created Successfully!',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #0066cc; color: white; padding: 30px 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .header h1 { margin: 0; font-size: 28px; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .welcome-box { background: white; padding: 20px; border-left: 4px solid #0066cc; margin: 20px 0; }
          .info-box { background: #EFF6FF; padding: 15px; border-radius: 8px; margin: 20px 0; }
          .info-box strong { color: #0066cc; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #666; font-size: 12px; }
          .button { display: inline-block; background: #0066cc; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; font-weight: bold; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Welcome to YCKF!</h1>
            <p style="margin: 10px 0 0 0; font-size: 16px;">Your Account Has Been Created Successfully</p>
          </div>
          <div class="content">
            <div class="welcome-box">
              <h2 style="margin-top: 0; color: #0066cc;">Hello ${userData.name}!</h2>
              <p>Thank you for joining the <strong>Young Cyber Knights Foundation (YCKF)</strong> community. Your account has been created successfully and is now active!</p>
            </div>

            <div class="info-box">
              <strong>📧 Your Account Details:</strong><br>
              <strong>Name:</strong> ${userData.name}<br>
              <strong>Email:</strong> ${userData.email}<br>
              <strong>Account Type:</strong> ${userData.role === 'admin' ? 'Administrator' : 'User'}<br>
              <strong>Created On:</strong> ${new Date().toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      hour12: true
    })}
            </div>

            <h3 style="color: #0066cc;">🚀 What's Next?</h3>
            <ul style="line-height: 2;">
              <li>✅ Login to the YCKF Mobile App with your credentials</li>
              <li>🔒 Enable premium features by subscribing or using coupon codes</li>
              <li>📚 Explore cybersecurity resources and educational content</li>
              <li>🛡️ Activate thief detection and device protection features</li>
              <li>📞 Book sessions with our cybersecurity experts</li>
            </ul>

            <div style="text-align: center;">
              <a href="yckf://login" class="button">Open YCKF App</a>
            </div>

            <div style="background: #FEF3C7; padding: 15px; border-radius: 8px; margin-top: 20px;">
              <strong style="color: #92400E;">🔐 Security Tip:</strong>
              <p style="margin: 10px 0 0 0; color: #92400E;">
                Keep your password secure and never share it with anyone. 
                If you didn't create this account, please contact us immediately at ${ADMIN_EMAIL}
              </p>
            </div>

            <div class="footer">
              <p><strong>Young Cyber Knights Foundation</strong></p>
              <p>Empowering the next generation of cybersecurity professionals</p>
              <p>
                Need help? Contact us at <a href="mailto:${ADMIN_EMAIL}" style="color: #0066cc;">${ADMIN_EMAIL}</a><br>
                Visit our website: <a href="https://youngcyberknightsfoundation.org" style="color: #0066cc;">youngcyberknightsfoundation.org</a>
              </p>
              <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
              <p style="font-size: 11px; color: #999;">
                This is an automated email from the YCKF Mobile App. Please do not reply to this email.
              </p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}
// ==========================ENDING============================


// ============================================
// AUTO-EMAIL: CYBERCRIME REPORT
// ============================================
async function sendCybercrimeReportEmail(reportData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const dateStr = new Date(reportData.dateOfIncident).toLocaleDateString();

  const mailOptions = {
    from: `"YCKF App" <${EMAIL_USER}>`,
    to: [ADMIN_EMAIL, BACKUP_EMAIL],
    subject: `Cybercrime Report - Case ID: ${reportData.caseId}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 700px; margin: 0 auto; padding: 20px; }
          .header { background: #dc2626; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .section { margin-bottom: 25px; }
          .section-title { font-size: 18px; font-weight: bold; color: #dc2626; margin-bottom: 10px; border-bottom: 2px solid #dc2626; padding-bottom: 5px; }
          .info-row { display: flex; margin-bottom: 8px; }
          .info-label { font-weight: bold; min-width: 180px; color: #555; }
          .info-value { color: #333; }
          .details-box { background: white; padding: 15px; border-left: 4px solid #dc2626; margin-top: 10px; }
          .map-link { display: inline-block; background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>��� CYBERCRIME REPORT</h1>
            <p>Case ID: ${reportData.caseId}</p>
          </div>
          <div class="content">
            <div class="section">
              <div class="section-title">REPORTER INFORMATION</div>
              <div class="info-row"><span class="info-label">Full Name:</span><span class="info-value">${reportData.fullName}</span></div>
              <div class="info-row"><span class="info-label">Email:</span><span class="info-value">${reportData.email}</span></div>
              <div class="info-row"><span class="info-label">Phone:</span><span class="info-value">${reportData.phoneNumber}</span></div>
              <div class="info-row"><span class="info-label">City/Location:</span><span class="info-value">${reportData.city}</span></div>
            </div>

            <div class="section">
              <div class="section-title">INCIDENT INFORMATION</div>
              <div class="info-row"><span class="info-label">Date of Incident:</span><span class="info-value">${dateStr}</span></div>
              <div class="info-row"><span class="info-label">Type of Cybercrime:</span><span class="info-value">${reportData.typeOfCybercrime}</span></div>
            </div>

            <div class="section">
              <div class="section-title">INCIDENT DETAILS</div>
              <div class="details-box">${reportData.details}</div>
            </div>

            ${reportData.location ? `
            <div class="section">
              <div class="section-title">GPS LOCATION</div>
              <div class="info-row"><span class="info-label">Coordinates:</span><span class="info-value">${reportData.location.latitude.toFixed(6)}, ${reportData.location.longitude.toFixed(6)}</span></div>
              ${reportData.location.accuracy ? `<div class="info-row"><span class="info-label">Accuracy:</span><span class="info-value">±${Math.round(reportData.location.accuracy)}m</span></div>` : ''}
              <a href="https://maps.google.com/?q=${reportData.location.latitude},${reportData.location.longitude}" class="map-link">View on Google Maps</a>
            </div>
            ` : ''}

            <div class="section">
              <div class="section-title">SUBMISSION INFO</div>
              <div class="info-row"><span class="info-label">Submitted via:</span><span class="info-value">YCKF Mobile App</span></div>
              <div class="info-row"><span class="info-label">Timestamp:</span><span class="info-value">${new Date().toLocaleString()}</span></div>
              ${reportData.userId ? `<div class="info-row"><span class="info-label">User ID:</span><span class="info-value">${reportData.userId}</span></div>` : ''}
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
    attachments: reportData.evidencePhotos && reportData.evidencePhotos.length > 0
      ? reportData.evidencePhotos.map((photo, index) => ({
        filename: `evidence_${index + 1}.jpg`,
        content: photo.split('base64,')[1] || photo,
        encoding: 'base64'
      }))
      : []
  };

  await emailTransporter.sendMail(mailOptions);
}

// ============================================
// AUTO-EMAIL: CONTACT MESSAGE
// ============================================
async function sendContactMessageEmail(contactData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const mailOptions = {
    from: `"YCKF App" <${EMAIL_USER}>`,
    to: [ADMIN_EMAIL, BACKUP_EMAIL],
    replyTo: contactData.email,
    subject: `Contact Form Submission from ${contactData.name}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #0066cc; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .section { margin-bottom: 20px; }
          .section-title { font-size: 16px; font-weight: bold; color: #0066cc; margin-bottom: 10px; border-bottom: 2px solid #0066cc; padding-bottom: 5px; }
          .info-row { margin-bottom: 8px; }
          .info-label { font-weight: bold; color: #555; }
          .message-box { background: white; padding: 15px; border-left: 4px solid #0066cc; margin-top: 10px; white-space: pre-wrap; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>��� CONTACT FORM MESSAGE</h1>
          </div>
          <div class="content">
            <div class="section">
              <div class="section-title">SENDER INFORMATION</div>
              <div class="info-row"><span class="info-label">Name:</span> ${contactData.name}</div>
              <div class="info-row"><span class="info-label">Email:</span> ${contactData.email}</div>
            </div>

            <div class="section">
              <div class="section-title">MESSAGE</div>
              <div class="message-box">${contactData.message}</div>
            </div>

            <div class="section">
              <div class="info-row"><span class="info-label">Sent via:</span> YCKF Mobile App</div>
              <div class="info-row"><span class="info-label">Timestamp:</span> ${new Date().toLocaleString()}</div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}

// ============================================
// AUTO-EMAIL: THIEF DETECTION EVIDENCE
// ============================================
async function sendThiefDetectionEvidenceEmail(evidenceData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const date = new Date(evidenceData.timestamp);
  const dateStr = date.toLocaleString('en-US', {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: true
  });

  const mailOptions = {
    from: `"YCKF Security Alert" <${EMAIL_USER}>`,
    to: [ADMIN_EMAIL, BACKUP_EMAIL],
    subject: '��� YCKF Security Alert - Unauthorized Access Detected',
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 700px; margin: 0 auto; padding: 20px; }
          .header { background: #dc2626; color: white; padding: 25px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .alert-box { background: #fee2e2; border-left: 4px solid #dc2626; padding: 15px; margin-bottom: 20px; }
          .section { margin-bottom: 25px; }
          .section-title { font-size: 18px; font-weight: bold; color: #dc2626; margin-bottom: 10px; border-bottom: 2px solid #dc2626; padding-bottom: 5px; }
          .info-row { margin-bottom: 8px; }
          .info-label { font-weight: bold; min-width: 150px; display: inline-block; color: #555; }
          .map-link { display: inline-block; background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 10px; }
          .actions-box { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 15px; margin-top: 20px; }
          .actions-box ol { margin: 10px 0; padding-left: 20px; }
          .footer { margin-top: 30px; padding-top: 20px; border-top: 2px solid #ddd; text-align: center; color: #666; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>⚠️ UNAUTHORIZED ACCESS DETECTED</h1>
            <p style="margin: 0; font-size: 14px;">YCKF Mobile Security System</p>
          </div>
          <div class="content">
            <div class="alert-box">
              <strong>SECURITY ALERT:</strong> An unauthorized unlock attempt has been detected on a YCKF protected device.
            </div>

            <div class="section">
              <div class="section-title">��� DETECTION DETAILS</div>
              <div class="info-row"><span class="info-label">Evidence ID:</span> ${evidenceData.evidenceId}</div>
              <div class="info-row"><span class="info-label">Timestamp:</span> ${dateStr}</div>
              <div class="info-row"><span class="info-label">Date/Time:</span> ${date.toLocaleDateString()} at ${date.toLocaleTimeString()}</div>
            </div>

            <div class="section">
              <div class="section-title">��� LOCATION INFORMATION</div>
              <div class="info-row"><span class="info-label">Latitude:</span> ${evidenceData.location.latitude.toFixed(6)}</div>
              <div class="info-row"><span class="info-label">Longitude:</span> ${evidenceData.location.longitude.toFixed(6)}</div>
              ${evidenceData.location.accuracy ? `<div class="info-row"><span class="info-label">Accuracy:</span> ±${Math.round(evidenceData.location.accuracy)} meters</div>` : ''}
              ${evidenceData.address ? `<div class="info-row"><span class="info-label">Address:</span> ${evidenceData.address}</div>` : ''}
              <a href="https://maps.google.com/?q=${evidenceData.location.latitude},${evidenceData.location.longitude}" class="map-link">��� View on Google Maps</a>
            </div>

            <div class="section">
              <div class="section-title">��� DEVICE INFORMATION</div>
              <div class="info-row"><span class="info-label">Model:</span> ${evidenceData.deviceModel || 'Unknown'}</div>
              <div class="info-row"><span class="info-label">Operating System:</span> ${evidenceData.deviceOS || 'Unknown'}</div>
              ${evidenceData.batteryLevel !== undefined ? `<div class="info-row"><span class="info-label">Battery Level:</span> ${evidenceData.batteryLevel}%</div>` : ''}
            </div>

            <div class="section">
              <div class="section-title">��� EVIDENCE CAPTURED</div>
              <div class="info-row"><span class="info-label">Type:</span> ${evidenceData.mediaType === 'photo' ? 'Photo (Front Camera)' : 'Video Recording'}</div>
              <div class="info-row"><span class="info-label">Media File:</span> Attached to this email</div>
              <div class="info-row"><span class="info-label">Capture Method:</span> Silent background capture</div>
            </div>

            <div class="actions-box">
              <strong>⚡ IMMEDIATE ACTIONS RECOMMENDED:</strong>
              <ol>
                <li>Review the attached evidence immediately</li>
                <li>Contact the device owner if registered in system</li>
                <li>Track device location if still active</li>
                <li>Consider reporting to local authorities if theft suspected</li>
                <li>Log incident in YCKF Security Dashboard</li>
              </ol>
            </div>

            <div class="footer">
              <p><strong>��� SECURITY NOTICE</strong></p>
              <p>This alert was automatically generated by the YCKF Mobile Security System.<br>
              The unauthorized user was NOT notified of the evidence capture.<br>
              All evidence has been securely transmitted and logged.</p>
              <hr style="margin: 20px 0; border: none; border-top: 1px solid #ddd;">
              <p><strong>Young Cyber Knights Foundation</strong><br>
              Security & Protection Division<br>
              Automated Security Alert System</p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
    attachments: evidenceData.mediaBase64 ? [{
      filename: `evidence_${evidenceData.evidenceId}.${evidenceData.mediaType === 'photo' ? 'jpg' : 'mp4'}`,
      content: evidenceData.mediaBase64,
      encoding: 'base64'
    }] : []
  };

  await emailTransporter.sendMail(mailOptions);
}


// ============================================
// AUTO-EMAIL: EMERGENCY REPORT
// ============================================
async function sendEmergencyReportEmail(reportData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const mailOptions = {
    from: `"YCKF Emergency Alert" <${EMAIL_USER}>`,
    to: [ADMIN_EMAIL, BACKUP_EMAIL],
    subject: `🚨 EMERGENCY REPORT - ${reportData.emergencyId}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 700px; margin: 0 auto; padding: 20px; }
          .header { background: #dc2626; color: white; padding: 25px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .section { margin-bottom: 25px; }
          .section-title { font-size: 18px; font-weight: bold; color: #dc2626; margin-bottom: 10px; border-bottom: 2px solid #dc2626; padding-bottom: 5px; }
          .info-row { margin-bottom: 8px; }
          .info-label { font-weight: bold; min-width: 150px; display: inline-block; color: #555; }
          .message-box { background: white; padding: 15px; border-left: 4px solid #dc2626; margin-top: 10px; white-space: pre-wrap; }
          .map-link { display: inline-block; background: #0066cc; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🚨 EMERGENCY REPORT</h1>
            <p style="margin: 0; font-size: 14px;">ID: ${reportData.emergencyId}</p>
          </div>
          <div class="content">
            <div class="section">
              <div class="section-title">📍 LOCATION INFORMATION</div>
              ${reportData.location ? `
                <div class="info-row"><span class="info-label">Coordinates:</span> ${reportData.location.latitude.toFixed(6)}, ${reportData.location.longitude.toFixed(6)}</div>
                ${reportData.location.accuracy ? `<div class="info-row"><span class="info-label">Accuracy:</span> ±${Math.round(reportData.location.accuracy)} meters</div>` : ''}
                <a href="https://maps.google.com/?q=${reportData.location.latitude},${reportData.location.longitude}" class="map-link">📍 View on Google Maps</a>
              ` : '<p>Location not available</p>'}
            </div>

            ${reportData.stationInfo ? `
            <div class="section">
              <div class="section-title">🚔 NEAREST POLICE STATION</div>
              <div class="info-row"><span class="info-label">Station:</span> ${reportData.stationInfo.name}</div>
              <div class="info-row"><span class="info-label">Distance:</span> ${reportData.stationInfo.distance.toFixed(2)} km</div>
              <div class="info-row"><span class="info-label">Phone:</span> ${reportData.stationInfo.phone}</div>
              <div class="info-row"><span class="info-label">Address:</span> ${reportData.stationInfo.address}</div>
            </div>
            ` : ''}

            <div class="section">
              <div class="section-title">📋 EMERGENCY DETAILS</div>
              <div class="info-row"><span class="info-label">Report Type:</span> ${reportData.reportType === 'voice' ? 'Voice Recording' : 'Text Message'}</div>
              ${reportData.hasAudio ? `<div class="info-row"><span class="info-label">Audio Duration:</span> ${reportData.audioDuration}</div>` : ''}
              ${reportData.textMessages ? `
                <div class="message-box">
                  <strong>Messages:</strong><br>
                  ${reportData.textMessages.map((msg, i) => `${i + 1}. ${msg}`).join('<br>')}
                </div>
              ` : ''}
              <div class="message-box">${reportData.message}</div>
            </div>

            <div class="section">
              <div class="section-title">⏰ TIMESTAMP</div>
              <div class="info-row"><span class="info-label">Reported At:</span> ${new Date(reportData.timestamp).toLocaleString()}</div>
              <div class="info-row"><span class="info-label">Submitted Via:</span> YCKF Mobile App</div>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}

// ============================================
// AUTO-EMAIL: BOOKING SUBMISSION
// ============================================
async function sendBookingSubmissionEmail(bookingData) {
  if (!emailTransporter) {
    throw new Error('Email service not configured');
  }

  const mailOptions = {
    from: `"YCKF Booking System" <${EMAIL_USER}>`,
    to: [ADMIN_EMAIL, BACKUP_EMAIL],
    replyTo: bookingData.phone ? `${bookingData.phone}` : undefined,
    subject: `📅 New Booking Request - ${bookingData.specialist}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: #1E40AF; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
          .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
          .section { margin-bottom: 20px; }
          .section-title { font-size: 16px; font-weight: bold; color: #1E40AF; margin-bottom: 10px; border-bottom: 2px solid #1E40AF; padding-bottom: 5px; }
          .info-row { margin-bottom: 8px; }
          .info-label { font-weight: bold; color: #555; }
          .case-box { background: white; padding: 15px; border-left: 4px solid #1E40AF; margin-top: 10px; white-space: pre-wrap; }
          .payment-badge { display: inline-block; background: #D1FAE5; color: #065F46; padding: 8px 16px; border-radius: 20px; font-weight: bold; margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>📅 NEW BOOKING REQUEST</h1>
            <p>YCKF Expert Service</p>
          </div>
          <div class="content">
            <div class="section">
              <div class="section-title">CLIENT INFORMATION</div>
              <div class="info-row"><span class="info-label">Full Name:</span> ${bookingData.fullName}</div>
              <div class="info-row"><span class="info-label">Phone Number:</span> ${bookingData.phone}</div>
            </div>

            <div class="section">
              <div class="section-title">APPOINTMENT DETAILS</div>
              <div class="info-row"><span class="info-label">Specialist:</span> ${bookingData.specialist}</div>
              <div class="info-row"><span class="info-label">Preferred Date:</span> ${bookingData.date}</div>
              <div class="info-row"><span class="info-label">Preferred Time:</span> ${bookingData.time}</div>
            </div>

            <div class="section">
              <div class="section-title">CASE DESCRIPTION</div>
              <div class="case-box">${bookingData.caseDescription}</div>
            </div>

            <div class="section">
              <div class="section-title">PAYMENT INFORMATION</div>
              <div class="info-row"><span class="info-label">Payment Method:</span> ${bookingData.paymentMethod}</div>
              <div class="info-row"><span class="info-label">Payment Reference:</span> ${bookingData.paymentReference}</div>
              ${bookingData.paymentReference !== 'Pending' ? '<span class="payment-badge">✓ Payment Confirmed</span>' : '<span class="payment-badge" style="background: #FEE2E2; color: #991B1B;">⏳ Payment Pending</span>'}
            </div>

            <div class="section">
              <div class="section-title">SUBMISSION INFO</div>
              <div class="info-row"><span class="info-label">Submitted via:</span> YCKF Mobile App</div>
              <div class="info-row"><span class="info-label">Timestamp:</span> ${new Date(bookingData.submittedAt).toLocaleString()}</div>
            </div>

            <div style="margin-top: 30px; padding: 15px; background: #EFF6FF; border-radius: 8px; text-align: center;">
              <p style="margin: 0; font-weight: bold; color: #1E40AF;">⚡ NEXT STEPS</p>
              <p style="margin: 10px 0 0 0; font-size: 14px;">
                1. Review the case description<br>
                2. Verify payment status<br>
                3. Contact client at ${bookingData.phone} to confirm appointment
              </p>
            </div>
          </div>
        </div>
      </body>
      </html>
    `
  };

  await emailTransporter.sendMail(mailOptions);
}

// ============================================
// ENDPOINT: POST /email/emergency-report
// ============================================
app.post('/email/emergency-report', emailLimiter, async (req, res) => {
  try {
    const reportData = req.body;

    // Validate required fields
    if (!reportData.emergencyId || !reportData.subject || !reportData.message) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields (emergencyId, subject, message)'
      });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not configured'
      });
    }

    console.log('🚨 Sending emergency report email:', reportData.emergencyId);

    await sendEmergencyReportEmail(reportData);

    logAudit('EMERGENCY_REPORT_EMAIL_SENT', reportData.emergencyId, null, {
      reportType: reportData.reportType
    });

    res.json({
      success: true,
      message: 'Emergency report sent successfully',
      emergencyId: reportData.emergencyId
    });

  } catch (error) {
    console.error('Failed to send emergency report:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send emergency report email'
    });
  }
});

// ENDPOINT: POST /email/booking-submission
app.post('/email/booking-submission', emailLimiter, async (req, res) => {
  try {
    const bookingData = req.body;

    // Validate required fields
    if (!bookingData.fullName || !bookingData.phone || !bookingData.date ||
      !bookingData.time || !bookingData.caseDescription || !bookingData.specialist) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields'
      });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not configured'
      });
    }

    console.log('📧 Sending booking submission email:', {
      specialist: bookingData.specialist,
      client: bookingData.fullName,
      date: bookingData.date
    });

    await sendBookingSubmissionEmail(bookingData);

    logAudit('BOOKING_SUBMISSION_SENT', bookingData.phone, null, {
      specialist: bookingData.specialist,
      client: bookingData.fullName
    });

    res.json({
      success: true,
      message: 'Booking submitted successfully',
      bookingReference: `YCKF-${Date.now()}`
    });

  } catch (error) {
    console.error('Failed to send booking submission:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send booking email'
    });
  }
});

// ============================================
// HEALTH CHECK
// ============================================
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    message: 'YCKF Backend API',
    version: '1.0.0',
    environment: NODE_ENV
  });
});

app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// ============================================
// AUTH ENDPOINTS (Existing - No Changes)
// ============================================
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // ⭐ Check database for existing email (case-insensitive)
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [normalizedEmail]
    );

    if (existingUser.rows.length > 0) {
      console.log(`❌ Registration blocked - Email exists: ${normalizedEmail}`);
      return res.status(400).json({
        error: 'An account with this email already exists. Please login instead.'
      });
    }

    // ⭐ Check for duplicate name (case-insensitive)
    const userName = name || email.split('@')[0];
    const existingName = await pool.query(
      'SELECT * FROM users WHERE LOWER(name) = LOWER($1)',
      [userName.toLowerCase().trim()]
    );

    if (existingName.rows.length > 0) {
      console.log(`❌ Registration blocked - Name already exists: ${userName}`);
      return res.status(400).json({
        error: 'This name is already registered. Please choose a different name.'
      });
    }

    // Validate password (userName already defined above)
    const passwordLower = password.toLowerCase();
    const nameParts = userName.toLowerCase().split(' ').filter(part => part.length > 2);
    const nameInPassword = nameParts.some(part => passwordLower.includes(part));

    if (nameInPassword) {
      return res.status(400).json({
        error: 'Password cannot contain your name or parts of your name. Please choose a stronger password.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters long'
      });
    }

    // ⭐ Insert into database
    const passwordHash = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    await pool.query(
      'INSERT INTO users (id, email, name, password_hash, role) VALUES ($1, $2, $3, $4, $5)',
      [userId, normalizedEmail, userName, passwordHash, 'user']
    );

    console.log(`✅ User registered: ${normalizedEmail} (ID: ${userId})`);
    await logAudit('USER_REGISTERED', userId, userId, { email: normalizedEmail });

    // Send account creation email
    if (emailTransporter) {
      try {
        await sendAccountCreationEmail({
          name: userName,
          email: normalizedEmail,
          role: 'user'
        });
        console.log(`✅ Welcome email sent to: ${normalizedEmail}`);
        await logAudit('ACCOUNT_CREATION_EMAIL_SENT', userId, userId, { email: normalizedEmail });
      } catch (emailError) {
        console.error('Email failed:', emailError);
      }
    }

    const token = jwt.sign(
      { id: userId, email: normalizedEmail, role: 'user' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: userId,
        email: normalizedEmail,
        name: userName,
        role: 'user'
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // ⭐ FIX: Query database (case-insensitive)
    const normalizedEmail = email.toLowerCase().trim();
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [normalizedEmail]
    );

    if (result.rows.length === 0) {
      console.log(`❌ Login failed - User not found: ${normalizedEmail}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      await logAudit('FAILED_LOGIN_ATTEMPT', normalizedEmail, user.id, { email: normalizedEmail });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await logAudit('USER_LOGIN', user.id, user.id, { email: normalizedEmail });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

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
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});


app.post('/auth/logout', authenticateToken, (req, res) => {
  logAudit('USER_LOGOUT', req.user.id, req.user.id, {});
  res.json({ success: true, message: 'Logged out successfully' });
});

app.get('/auth/me', authenticateToken, async (req, res) => {
  try {
    // ⭐ FIX: Query from database
    const result = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// ============================================
// PASSWORD RESET ENDPOINTS (Existing - No Changes)
// ============================================
app.post('/auth/forgot-password', resetPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        error: 'Email service is not configured. Please contact support.'
      });
    }

    // ⭐ FIX: Query database
    const normalizedEmail = email.toLowerCase().trim();  // ✅ ONLY ONE DECLARATION
    const result = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [normalizedEmail]
    );
    const user = result.rows.length > 0 ? result.rows[0] : null;

    if (!user) {
      console.log(`Password reset requested for non-existent email: ${email}`);
      return res.json({
        success: true,
        message: 'If an account exists with this email, a reset code has been sent.'
      });
    }

    const code = generateResetCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    // ⭐ FIX: Save to database (normalizedEmail already declared above)
    await pool.query(
      'INSERT INTO reset_codes (email, code, expires_at, used) VALUES ($1, $2, $3, $4)',
      [normalizedEmail, code, expiresAt, false]
    );

    try {
      await sendResetCodeEmail(email, code, user.name);
      logAudit('PASSWORD_RESET_REQUESTED', user.id, user.id, { email });

      res.json({
        success: true,
        message: 'Password reset code has been sent to your email.'
      });
    } catch (emailError) {
      console.error('Failed to send reset email:', emailError);
      return res.status(500).json({
        error: 'Failed to send reset code. Please try again later.'
      });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process password reset request' });
  }
});

app.post('/auth/verify-reset-code', resetPasswordLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code are required' });
    }

    // ⭐ FIX: Query database
    const normalizedEmail = email.toLowerCase().trim();
    const result = await pool.query(
      `SELECT * FROM reset_codes 
   WHERE LOWER(email) = LOWER($1) 
   AND code = $2 
   AND used = false 
   AND expires_at > NOW()
   ORDER BY created_at DESC
   LIMIT 1`,
      [normalizedEmail, code]
    );
    const resetCode = result.rows.length > 0 ? result.rows[0] : null;
    if (!resetCode) {
      return res.status(400).json({
        error: 'Invalid or expired reset code'
      });
    }

    logAudit('PASSWORD_RESET_CODE_VERIFIED', email, null, { email });

    res.json({
      success: true,
      message: 'Reset code verified successfully'
    });
  } catch (error) {
    console.error('Verify reset code error:', error);
    res.status(500).json({ error: 'Failed to verify reset code' });
  }
});

app.post('/auth/reset-password', resetPasswordLimiter, async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
      return res.status(400).json({
        error: 'Email, code, and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        error: 'Password must be at least 8 characters long'
      });
    }

    // ⭐ FIX: Query database
    const normalizedEmail = email.toLowerCase().trim();
    const result = await pool.query(
      `SELECT * FROM reset_codes 
   WHERE LOWER(email) = LOWER($1) 
   AND code = $2 
   AND used = false 
   AND expires_at > NOW()
   ORDER BY created_at DESC
   LIMIT 1`,
      [normalizedEmail, code]
    );
    const resetCode = result.rows.length > 0 ? result.rows[0] : null;
    if (!resetCode) {
      return res.status(400).json({
        error: 'Invalid or expired reset code'
      });
    }

    // ⭐ FIX: Get user from database
    const userResult = await pool.query(
      'SELECT * FROM users WHERE LOWER(email) = LOWER($1)',
      [normalizedEmail]
    );
    const user = userResult.rows.length > 0 ? userResult.rows[0] : null; if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // ============================================
    // NEW: VALIDATE PASSWORD DOESN'T CONTAIN NAME
    // ============================================
    const passwordLower = newPassword.toLowerCase();

    // Split name into parts (first name, last name, etc.)
    const nameParts = user.name.toLowerCase().split(' ').filter(part => part.length > 2);

    // Check if any name part is in the password
    const nameInPassword = nameParts.some(part => passwordLower.includes(part));

    if (nameInPassword) {
      return res.status(400).json({
        error: 'Password cannot contain your name or parts of your name. Please choose a stronger password.'
      });
    }

    // ============================================
    // NEW: VALIDATE PASSWORD IS DIFFERENT FROM OLD PASSWORD
    // ============================================
    const isSamePassword = await bcrypt.compare(newPassword, user.password_hash);

    if (isSamePassword) {
      return res.status(400).json({
        error: 'New password cannot be the same as your old password. Please choose a different password.'
      });
    }

    // ⭐ FIX: Update password in database
    const newPasswordHash = await bcrypt.hash(newPassword, 10);
    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [newPasswordHash, user.id]
    );

    // Mark reset code as used
    await pool.query(
      'UPDATE reset_codes SET used = true WHERE id = $1',
      [resetCode.id]
    );

    logAudit('PASSWORD_RESET_COMPLETED', user.id, user.id, { email });

    res.json({
      success: true,
      message: 'Password has been reset successfully. Please login with your new password.'
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});
// ============================================
// AUTO-EMAIL ENDPOINTS
// ============================================

// 1. AUTO-SEND CYBERCRIME REPORT
app.post('/email/cybercrime-report', authenticateToken, emailLimiter, async (req, res) => {
  try {
    const reportData = req.body;

    if (!reportData.caseId || !reportData.fullName || !reportData.email) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields (caseId, fullName, email)'
      });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not configured'
      });
    }

    // Add user ID to report
    reportData.userId = req.user.id;

    console.log('��� Sending cybercrime report email:', reportData.caseId);

    await sendCybercrimeReportEmail(reportData);

    logAudit('CYBERCRIME_REPORT_SENT', req.user.id, null, {
      caseId: reportData.caseId
    });

    res.json({
      success: true,
      message: 'Cybercrime report sent successfully'
    });

  } catch (error) {
    console.error('Failed to send cybercrime report:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send cybercrime report email'
    });
  }
});

// 2. AUTO-SEND CONTACT MESSAGE
app.post('/email/contact-message', emailLimiter, async (req, res) => {
  try {
    const contactData = req.body;

    if (!contactData.name || !contactData.email || !contactData.message) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields (name, email, message)'
      });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not configured'
      });
    }

    console.log('��� Sending contact message from:', contactData.email);

    await sendContactMessageEmail(contactData);

    logAudit('CONTACT_MESSAGE_SENT', contactData.email, null, {
      name: contactData.name
    });

    res.json({
      success: true,
      message: 'Contact message sent successfully'
    });

  } catch (error) {
    console.error('Failed to send contact message:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send contact message email'
    });
  }
});

// 3. AUTO-SEND THIEF DETECTION EVIDENCE (NO AUTH REQUIRED - SECURITY FEATURE)
app.post('/email/thief-detection', emailLimiter, async (req, res) => {
  try {
    const evidenceData = req.body;

    if (!evidenceData.evidenceId || !evidenceData.location) {
      return res.status(400).json({
        success: false,
        error: 'Missing required fields (evidenceId, location)'
      });
    }

    if (!emailTransporter) {
      return res.status(503).json({
        success: false,
        error: 'Email service not configured'
      });
    }

    console.log('��� SECURITY ALERT - Sending thief detection evidence:', evidenceData.evidenceId);

    await sendThiefDetectionEvidenceEmail(evidenceData);

    logAudit('THIEF_DETECTION_ALERT_SENT', 'SYSTEM', null, {
      evidenceId: evidenceData.evidenceId
    });

    res.json({
      success: true,
      message: 'Thief detection evidence sent successfully'
    });

  } catch (error) {
    console.error('Failed to send thief detection evidence:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to send thief detection evidence email'
    });
  }
});

// ============================================
// REMAINING ENDPOINTS (No Changes)
// ============================================

app.get('/entitlements', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    // ⭐ FIX: Get user from database
    const userResult = await pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];

    // Check if user is admin
    if (user.role === 'admin') {
      return res.json({
        premium: true,
        reason: 'admin',
        adminRole: true,
        subscriptionActive: false,
        couponSessionActive: false,
        demoSessionActive: false
      });
    }

    // ⭐ FIX: Check for active subscription in database
    const subscriptionResult = await pool.query(
      `SELECT * FROM subscriptions 
       WHERE user_id = $1 
       AND is_active = true 
       AND expires_at > NOW()
       LIMIT 1`,
      [userId]
    );

    if (subscriptionResult.rows.length > 0) {
      const subscription = subscriptionResult.rows[0];
      return res.json({
        premium: true,
        reason: 'subscription',
        adminRole: false,
        subscriptionActive: true,
        couponSessionActive: false,
        demoSessionActive: false,
        expiresAt: subscription.expires_at
      });
    }

    // ⭐ FIX: Check for active coupon redemption in database
    const couponResult = await pool.query(
      `SELECT * FROM coupon_redemptions 
       WHERE user_id = $1 
       AND is_active = true 
       AND expires_at > NOW()
       LIMIT 1`,
      [userId]
    );

    if (couponResult.rows.length > 0) {
      const activeCoupon = couponResult.rows[0];
      const timeRemaining = Math.floor((new Date(activeCoupon.expires_at) - new Date()) / 60000);
      return res.json({
        premium: true,
        reason: 'coupon',
        adminRole: false,
        subscriptionActive: false,
        couponSessionActive: true,
        demoSessionActive: false,
        expiresAt: activeCoupon.expires_at,
        timeRemaining
      });
    }

    // ⭐ FIX: Check for active demo session in database
    const demoResult = await pool.query(
      `SELECT * FROM demo_sessions 
       WHERE user_id = $1 
       AND is_active = true 
       AND expires_at > NOW()
       LIMIT 1`,
      [userId]
    );

    if (demoResult.rows.length > 0) {
      const demoSession = demoResult.rows[0];
      const timeRemaining = Math.floor((new Date(demoSession.expires_at) - new Date()) / 60000);
      return res.json({
        premium: true,
        reason: 'demo',
        adminRole: false,
        subscriptionActive: false,
        couponSessionActive: false,
        demoSessionActive: true,
        expiresAt: demoSession.expires_at,
        timeRemaining
      });
    }

    // No premium access
    res.json({
      premium: false,
      reason: 'none',
      adminRole: false,
      subscriptionActive: false,
      couponSessionActive: false,
      demoSessionActive: false
    });

  } catch (error) {
    console.error('Entitlements check error:', error);
    res.status(500).json({ error: 'Failed to check entitlements' });
  }
});


app.post('/subscriptions/activate', authenticateToken, (req, res) => {
  try {
    const { paymentReference, paymentMethod } = req.body;
    const userId = req.user.id;

    const activatedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();

    const subscription = {
      id: uuidv4(),
      userId,
      isActive: true,
      activatedAt,
      expiresAt,
      paymentReference,
      paymentMethod
    };

    subscriptions.push(subscription);

    logAudit('SUBSCRIPTION_ACTIVATED', userId, userId, {
      paymentReference,
      paymentMethod
    });

    res.json({
      success: true,
      subscription: {
        activatedAt,
        expiresAt
      }
    });
  } catch (error) {
    console.error('Subscription activation error:', error);
    res.status(500).json({ error: 'Failed to activate subscription' });
  }
});

// app.post('/coupons/validate', authenticateToken, couponLimiter, (req, res) => {
//   try {
//     const { couponCode } = req.body;
// ✅ CORRECT
app.post('/coupons/validate', authenticateToken, couponLimiter, async (req, res) => {
  try {
    const { couponCode } = req.body;

    if (!couponCode) {
      return res.status(400).json({ valid: false, message: 'Coupon code required' });
    }

    // ⭐ Get coupon from database
    const couponResult = await pool.query(
      'SELECT * FROM coupons WHERE UPPER(code) = UPPER($1)',
      [couponCode]
    );

    if (couponResult.rows.length === 0) {
      return res.json({
        valid: false,
        message: 'Coupon code not found',
      });
    }

    const coupon = couponResult.rows[0];

    // ⭐ FIX: Check is_active (database column name with underscore)
    if (!coupon.is_active) {
      return res.json({ valid: false, message: 'This coupon has been deactivated' });
    }

    // ⭐ FIX: Check expires_at (database column name with underscore)
    if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
      return res.json({ valid: false, message: 'This coupon has expired' });
    }

    // ⭐ FIX: Check max_redemptions (database column name with underscore)
    if (coupon.max_redemptions && coupon.current_redemptions >= coupon.max_redemptions) {
      return res.json({ valid: false, message: 'This coupon has reached its maximum usage limit' });
    }

    res.json({
      valid: true,
      message: 'Coupon is valid',
      description: coupon.description,
      durationType: coupon.duration_type,  // ⭐ Return duration type to user
      maxRedemptions: coupon.max_redemptions,
      currentRedemptions: coupon.current_redemptions
    });
  } catch (error) {
    console.error('Coupon validation error:', error);
    res.status(500).json({ valid: false, message: 'Validation failed' });
  }
});


app.post('/coupons/redeem', authenticateToken, async (req, res) => {
  try {
    const { couponCode } = req.body;
    const userId = req.user.id;

    if (!couponCode) {
      return res.status(400).json({ error: 'Coupon code required' });
    }

    // ⭐ Get coupon from database
    const couponResult = await pool.query(
      'SELECT * FROM coupons WHERE UPPER(code) = UPPER($1) AND is_active = true',
      [couponCode.trim()]
    );

    if (couponResult.rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found or inactive' });
    }

    const coupon = couponResult.rows[0];

    // Check if coupon has expired
    if (coupon.expires_at && new Date(coupon.expires_at) < new Date()) {
      return res.status(400).json({ error: 'This coupon has expired' });
    }

    // Check max redemptions
    if (coupon.max_redemptions && coupon.current_redemptions >= coupon.max_redemptions) {
      return res.status(400).json({ error: 'Coupon usage limit reached' });
    }

    // ⭐ Check for existing active redemption
    const existingRedemption = await pool.query(
      `SELECT * FROM coupon_redemptions 
       WHERE user_id = $1 
       AND is_active = true 
       AND expires_at > NOW()
       LIMIT 1`,
      [userId]
    );

    if (existingRedemption.rows.length > 0) {
      const existing = existingRedemption.rows[0];
      return res.status(400).json({
        error: 'You already have an active coupon session',
        expiresAt: existing.expires_at
      });
    }

    // ⭐ Calculate expiry based on ADMIN-SET duration from coupon
    let durationMs;
    switch (coupon.duration_type) {
      case '12h':
        durationMs = 12 * 60 * 60 * 1000;
        break;
      case '24h':
        durationMs = 24 * 60 * 60 * 1000;
        break;
      case '12months':
        durationMs = 365 * 24 * 60 * 60 * 1000;
        break;
      default:
        durationMs = 24 * 60 * 60 * 1000;
    }

    const expiresAt = new Date(Date.now() + durationMs);
    const accessDuration = Math.floor(durationMs / (60 * 1000)); // in minutes
    const redemptionId = uuidv4();

    // ⭐ Insert redemption into database
    await pool.query(
      `INSERT INTO coupon_redemptions (id, coupon_code, user_id, redeemed_at, expires_at, is_active, access_duration)
       VALUES ($1, $2, $3, NOW(), $4, $5, $6)`,
      [redemptionId, coupon.code, userId, expiresAt, true, accessDuration]
    );

    // ⭐ Increment redemption count
    await pool.query(
      'UPDATE coupons SET current_redemptions = current_redemptions + 1 WHERE id = $1',
      [coupon.id]
    );

    console.log(`✅ Coupon redeemed: ${coupon.code} by user ${userId}`);

    await logAudit('COUPON_REDEEMED', userId, userId, {
      couponCode: coupon.code,
      durationType: coupon.duration_type
    });

    res.json({
      success: true,
      redemption: {
        redeemedAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        accessDuration: accessDuration,
        durationType: coupon.duration_type
      },
      message: `Coupon redeemed! You now have ${coupon.duration_type} of premium access.`
    });
  } catch (error) {
    console.error('❌ Coupon redemption error:', error);
    res.status(500).json({ error: 'Failed to redeem coupon' });
  }
});

app.post('/admin/demo/activate', authenticateToken, couponLimiter, async (req, res) => {
  try {
    const { demoToken, deviceId } = req.body;
    const userId = req.user.id;

    if (!demoToken) {
      return res.status(400).json({ error: 'Demo token required' });
    }

    const validToken = await bcrypt.compare(demoToken, currentDemoToken);

    if (!validToken) {
      logAudit('FAILED_DEMO_TOKEN_ATTEMPT', userId, userId, { deviceId });
      return res.status(401).json({ error: 'Invalid demo token' });
    }

    const existingSession = demoSessions.find(
      s => s.userId === userId && s.isActive && new Date(s.expiresAt) > new Date()
    );

    if (existingSession) {
      const timeRemaining = Math.floor((new Date(existingSession.expiresAt) - new Date()) / 60000);
      return res.json({
        success: true,
        premium: true,
        reason: 'demo',
        demoSessionActive: true,
        expiresAt: existingSession.expiresAt,
        timeRemaining,
        message: 'Demo session already active'
      });
    }

    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    const demoSession = {
      id: uuidv4(),
      userId,
      token: demoToken,
      expiresAt,
      isActive: true,
      deviceId
    };

    demoSessions.push(demoSession);

    logAudit('DEMO_SESSION_ACTIVATED', userId, userId, { deviceId });

    res.json({
      success: true,
      premium: true,
      reason: 'demo',
      demoSessionActive: true,
      expiresAt,
      timeRemaining: 60
    });
  } catch (error) {
    console.error('Demo activation error:', error);
    res.status(500).json({ error: 'Failed to activate demo session' });
  }
});

app.post('/admin/coupons/create', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { code, description, durationType, expiresAt, maxRedemptions } = req.body;

    console.log('📝 Coupon creation request:', { code, durationType, expiresAt, maxRedemptions });

    // ⭐ Validate duration type
    const validDurations = ['12h', '24h', '12months'];
    if (durationType && !validDurations.includes(durationType)) {
      return res.status(400).json({
        error: 'Invalid duration type. Must be 12h, 24h, or 12months'
      });
    }

    if (!code) {
      return res.status(400).json({ error: 'Coupon code required' });
    }

    // ⭐ Check database for existing coupon
    const existingCoupon = await pool.query(
      'SELECT * FROM coupons WHERE UPPER(code) = UPPER($1)',
      [code.trim()]
    );

    if (existingCoupon.rows.length > 0) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }

    const couponId = uuidv4();

    // ⭐ FIX: Safely handle expiresAt date conversion
    let expiresAtTimestamp = null;
    if (expiresAt && expiresAt.trim() !== '') {
      try {
        const dateObj = new Date(expiresAt);
        if (!isNaN(dateObj.getTime())) {
          expiresAtTimestamp = dateObj.toISOString();
        } else {
          console.log('⚠️  Invalid expiresAt date, using null');
        }
      } catch (e) {
        console.log('⚠️  Date parsing error, using null:', e.message);
      }
    }

    await pool.query(
      `INSERT INTO coupons (id, code, is_active, description, duration_type, expires_at, max_redemptions, current_redemptions, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        couponId,
        code.toUpperCase().trim(),
        true,
        description || null,
        durationType || '24h',
        expiresAtTimestamp,
        maxRedemptions || null,
        0,
        req.user.email
      ]
    );

    console.log(`✅ Coupon created: ${code.toUpperCase()}`);

    const newCoupon = {
      id: couponId,
      code: code.toUpperCase().trim(),
      isActive: true,
      durationType: durationType || '24h',
      description: description || null,
      expiresAt: expiresAtTimestamp,
      maxRedemptions: maxRedemptions || null,
      currentRedemptions: 0,
      createdBy: req.user.email,
      createdAt: new Date().toISOString()
    };

    await logAudit('COUPON_CREATED', req.user.id, null, { 
      code: code.toUpperCase(),
      durationType: durationType || '24h'
    });

    res.json({
      success: true,
      coupon: newCoupon,
      message: 'Coupon created successfully'
    });
  } catch (error) {
    console.error('❌ Coupon creation error:', error);
    res.status(500).json({ 
      error: 'Failed to create coupon',
      details: error.message 
    });
  }
});

app.get('/admin/coupons', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM coupons ORDER BY created_at DESC'
    );

    res.json({ coupons: result.rows });
  } catch (error) {
    console.error('Get coupons error:', error);
    res.status(500).json({ error: 'Failed to fetch coupons' });
  }
});

app.post('/admin/coupons/deactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { code } = req.body;

    // ⭐ FIX: Update in database
    const result = await pool.query(
      'UPDATE coupons SET is_active = false WHERE UPPER(code) = UPPER($1) RETURNING *',
      [code.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    await logAudit('COUPON_DEACTIVATED', req.user.id, null, { code });

    res.json({ success: true, message: 'Coupon deactivated' });
  } catch (error) {
    console.error('Coupon deactivation error:', error);
    res.status(500).json({ error: 'Failed to deactivate coupon' });
  }
});

app.post('/admin/coupons/reactivate', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { code } = req.body;

    // ⭐ FIX: Update in database
    const result = await pool.query(
      'UPDATE coupons SET is_active = true WHERE UPPER(code) = UPPER($1) RETURNING *',
      [code.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    await logAudit('COUPON_REACTIVATED', req.user.id, null, { code });

    res.json({ success: true, message: 'Coupon reactivated' });
  } catch (error) {
    console.error('Coupon reactivation error:', error);
    res.status(500).json({ error: 'Failed to reactivate coupon' });
  }
});

app.get('/admin/redemptions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM coupon_redemptions ORDER BY redeemed_at DESC'
    );

    res.json({ redemptions: result.rows });
  } catch (error) {
    console.error('Get redemptions error:', error);
    res.status(500).json({ error: 'Failed to fetch redemptions' });
  }
});

app.get('/admin/audit-logs', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    
    const result = await pool.query(
      'SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT $1',
      [limit]
    );

    res.json({ logs: result.rows });
  } catch (error) {
    console.error('Get audit logs error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

app.post('/admin/demo/rotate-token', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { newToken } = req.body;

    if (!newToken) {
      return res.status(400).json({ error: 'New token required' });
    }

    currentDemoToken = await bcrypt.hash(newToken, 10);
    demoSessions.forEach(s => { s.isActive = false; });

    logAudit('DEMO_TOKEN_ROTATED', req.user.id, null, {});

    res.json({
      success: true,
      message: 'Demo token rotated and all sessions revoked'
    });
  } catch (error) {
    console.error('Token rotation error:', error);
    res.status(500).json({ error: 'Failed to rotate token' });
  }
});

// CLEANUP
// Cleanup expired coupons/demo sessions (using database)
setInterval(async () => {
  try {
    // Deactivate expired coupon redemptions
    await pool.query(
      `UPDATE coupon_redemptions 
       SET is_active = false 
       WHERE is_active = true 
       AND expires_at < NOW()`
    );

    // Deactivate expired demo sessions
    await pool.query(
      `UPDATE demo_sessions 
       SET is_active = false 
       WHERE is_active = true 
       AND expires_at < NOW()`
    );
  } catch (error) {
    console.error('Cleanup interval error:', error);
  }
}, 60000);


app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ⭐ FIX: Initialize database before starting server
(async () => {
  try {
    await initializeDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀 YCKF Backend Server running on port ${PORT}`);
      console.log(`🌍 Environment: ${NODE_ENV}`);
      console.log(`🗄️  Database: PostgreSQL Connected ✅`);
      console.log(`🌐 Listening on: 0.0.0.0:${PORT}`);
      console.log(`\n📧 Default Admin:`);
      console.log(`   Email: admin@yckf.org`);
      console.log(`   Password: SecureAdmin@2024`);
      console.log(`\n✅ Server ready to accept requests\n`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
})();
module.exports = app;