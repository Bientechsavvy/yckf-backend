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
require('dotenv').config();

const app = express();

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
// IN-MEMORY DATABASES
// ============================================
const users = [
  {
    id: 'user-1',
    email: 'admin@yckf.org',
    name: 'YCKF Admin',
    passwordHash: bcrypt.hashSync('SecureAdmin@2024', 10),
    role: 'admin',
    createdAt: new Date().toISOString(),
  },
  {
    id: 'user-2',
    email: 'user@yckf.org',
    name: 'Test User',
    passwordHash: bcrypt.hashSync('TestUser@2024', 10),
    role: 'user',
    createdAt: new Date().toISOString(),
  }
];

const subscriptions = [];
const coupons = [];
const couponRedemptions = [];
const demoSessions = [];
const auditLogs = [];
const resetCodes = [];

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
function logAudit(action, performedBy, targetUser, details) {
  auditLogs.push({
    timestamp: new Date().toISOString(),
    action,
    performedBy,
    targetUser,
    details
  });
  console.log(`[AUDIT] ${action} by ${performedBy}`, details);
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

    const existingUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
          id: uuidv4(),
      email: email.toLowerCase(),
      name: name || email.split('@')[0],
      passwordHash,
      role: 'user',
      createdAt: new Date().toISOString(),
    };

    users.push(newUser);
    logAudit('USER_REGISTERED', newUser.id, newUser.id, { email: newUser.email });

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role
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

    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.passwordHash);
    if (!validPassword) {
      logAudit('FAILED_LOGIN_ATTEMPT', email, user.id, { email });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    logAudit('USER_LOGIN', user.id, user.id, { email });

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

app.get('/auth/me', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === req.user.id);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role
  });
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

    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    
    if (!user) {
      console.log(`Password reset requested for non-existent email: ${email}`);
      return res.json({ 
        success: true, 
        message: 'If an account exists with this email, a reset code has been sent.' 
      });
    }

    const code = generateResetCode();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    resetCodes.push({
      email: email.toLowerCase(),
      code,
      expiresAt,
      used: false,
      createdAt: new Date().toISOString()
    });

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

app.post('/auth/verify-reset-code', resetPasswordLimiter, (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: 'Email and code are required' });
    }

    const resetCode = resetCodes.find(
      rc => rc.email.toLowerCase() === email.toLowerCase() && 
            rc.code === code &&
            !rc.used &&
            new Date(rc.expiresAt) > new Date()
    );

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

    if (newPassword.length < 6) {
      return res.status(400).json({ 
        error: 'Password must be at least 6 characters long' 
      });
    }

    const resetCode = resetCodes.find(
      rc => rc.email.toLowerCase() === email.toLowerCase() && 
            rc.code === code &&
            !rc.used &&
            new Date(rc.expiresAt) > new Date()
    );

    if (!resetCode) {
      return res.status(400).json({ 
        error: 'Invalid or expired reset code' 
      });
    }

    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.passwordHash = await bcrypt.hash(newPassword, 10);
    resetCode.used = true;

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

app.get('/entitlements', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const user = users.find(u => u.id === userId);

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

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

  const subscription = subscriptions.find(
    s => s.userId === userId && s.isActive && new Date(s.expiresAt) > new Date()
  );
  if (subscription) {
    return res.json({
      premium: true,
      reason: 'subscription',
      adminRole: false,
      subscriptionActive: true,
      couponSessionActive: false,
      demoSessionActive: false,
      expiresAt: subscription.expiresAt
    });
  }

  const activeCoupon = couponRedemptions.find(
    r => r.userId === userId && r.isActive && new Date(r.expiresAt) > new Date()
  );
  if (activeCoupon) {
    const timeRemaining = Math.floor((new Date(activeCoupon.expiresAt) - new Date()) / 60000);
    return res.json({
      premium: true,
      reason: 'coupon',
      adminRole: false,
      subscriptionActive: false,
      couponSessionActive: true,
      demoSessionActive: false,
      expiresAt: activeCoupon.expiresAt,
      timeRemaining
    });
  }

  const demoSession = demoSessions.find(
    s => s.userId === userId && s.isActive && new Date(s.expiresAt) > new Date()
  );
  if (demoSession) {
    const timeRemaining = Math.floor((new Date(demoSession.expiresAt) - new Date()) / 60000);
    return res.json({
      premium: true,
      reason: 'demo',
      adminRole: false,
      subscriptionActive: false,
      couponSessionActive: false,
      demoSessionActive: true,
      expiresAt: demoSession.expiresAt,
      timeRemaining
    });
  }

  res.json({
    premium: false,
    reason: 'none',
    adminRole: false,
    subscriptionActive: false,
    couponSessionActive: false,
    demoSessionActive: false
  });
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

app.post('/coupons/validate', authenticateToken, couponLimiter, (req, res) => {
  try {
    const { couponCode } = req.body;

    if (!couponCode) {
      return res.status(400).json({ valid: false, message: 'Coupon code required' });
    }

    const coupon = coupons.find(c => c.code.toUpperCase() === couponCode.toUpperCase());

    if (!coupon) {
      return res.json({ valid: false, message: 'Invalid coupon code' });
    }

    if (!coupon.isActive) {
      return res.json({ valid: false, message: 'This coupon has been deactivated' });
    }

    if (coupon.expiresAt && new Date(coupon.expiresAt) < new Date()) {
      return res.json({ valid: false, message: 'This coupon has expired' });
    }

    if (coupon.maxRedemptions && coupon.currentRedemptions >= coupon.maxRedemptions) {
      return res.json({ valid: false, message: 'This coupon has reached its maximum usage limit' });
    }

    res.json({
      valid: true,
      message: 'Coupon is valid',
      description: coupon.description,
      maxRedemptions: coupon.maxRedemptions,
      currentRedemptions: coupon.currentRedemptions
    });
  } catch (error) {
    console.error('Coupon validation error:', error);
    res.status(500).json({ valid: false, message: 'Validation failed' });
  }
});

app.post('/coupons/redeem', authenticateToken, couponLimiter, (req, res) => {
  try {
    const { couponCode, durationHours } = req.body;
    const userId = req.user.id;

    if (!couponCode || !durationHours) {
      return res.status(400).json({ error: 'Coupon code and duration required' });
    }

    if (![12, 24].includes(durationHours)) {
      return res.status(400).json({ error: 'Duration must be 12 or 24 hours' });
    }

    const coupon = coupons.find(c => c.code.toUpperCase() === couponCode.toUpperCase());

    if (!coupon || !coupon.isActive) {
      return res.status(400).json({ error: 'Invalid or inactive coupon' });
    }

    if (coupon.maxRedemptions && coupon.currentRedemptions >= coupon.maxRedemptions) {
      return res.status(400).json({ error: 'Coupon usage limit reached' });
    }

    const existingRedemption = couponRedemptions.find(
      r => r.userId === userId && r.isActive && new Date(r.expiresAt) > new Date()
    );

    if (existingRedemption) {
      return res.status(400).json({ 
        error: 'You already have an active coupon session',
        expiresAt: existingRedemption.expiresAt
      });
    }

    const redeemedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + durationHours * 60 * 60 * 1000).toISOString();

    const redemption = {
      id: uuidv4(),
      couponCode: coupon.code,
      userId,
      redeemedAt,
      expiresAt,
      isActive: true,
      accessDuration: durationHours
    };

    couponRedemptions.push(redemption);
    coupon.currentRedemptions++;

    logAudit('COUPON_REDEEMED', userId, userId, { 
      couponCode: coupon.code, 
      durationHours 
    });

    res.json({
      success: true,
      redemption: {
        redeemedAt,
        expiresAt,
        accessDuration: durationHours
      }
    });
  } catch (error) {
    console.error('Coupon redemption error:', error);
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

app.post('/admin/coupons/create', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { code, description, expiresAt, maxRedemptions } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Coupon code required' });
    }

    const existingCoupon = coupons.find(c => c.code.toUpperCase() === code.toUpperCase());
    if (existingCoupon) {
      return res.status(400).json({ error: 'Coupon code already exists' });
    }

    const coupon = {
      id: uuidv4(),
      code: code.toUpperCase(),
      isActive: true,
      createdAt: new Date().toISOString(),
      createdBy: req.user.email,
      expiresAt: expiresAt || null,
      maxRedemptions: maxRedemptions || null,
      currentRedemptions: 0,
      description: description || null
    };

    coupons.push(coupon);

    logAudit('COUPON_CREATED', req.user.id, null, { code: coupon.code });

    res.json({
      success: true,
      coupon
    });
  } catch (error) {
    console.error('Coupon creation error:', error);
    res.status(500).json({ error: 'Failed to create coupon' });
  }
});

app.get('/admin/coupons', authenticateToken, requireAdmin, (req, res) => {
  res.json({ coupons });
});

app.post('/admin/coupons/deactivate', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { code } = req.body;

    const coupon = coupons.find(c => c.code.toUpperCase() === code.toUpperCase());
    if (!coupon) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    coupon.isActive = false;

    logAudit('COUPON_DEACTIVATED', req.user.id, null, { code });

    res.json({ success: true, message: 'Coupon deactivated' });
  } catch (error) {
    console.error('Coupon deactivation error:', error);
    res.status(500).json({ error: 'Failed to deactivate coupon' });
  }
});

app.post('/admin/coupons/reactivate', authenticateToken, requireAdmin, (req, res) => {
  try {
    const { code } = req.body;

    const coupon = coupons.find(c => c.code.toUpperCase() === code.toUpperCase());
    if (!coupon) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    coupon.isActive = true;

    logAudit('COUPON_REACTIVATED', req.user.id, null, { code });

    res.json({ success: true, message: 'Coupon reactivated' });
  } catch (error) {
    console.error('Coupon reactivation error:', error);
    res.status(500).json({ error: 'Failed to reactivate coupon' });
  }
});

app.get('/admin/redemptions', authenticateToken, requireAdmin, (req, res) => {
  res.json({ redemptions: couponRedemptions });
});

app.get('/admin/audit-logs', authenticateToken, requireAdmin, (req, res) => {
  const limit = parseInt(req.query.limit) || 100;
  const logs = auditLogs.slice(-limit).reverse();
  res.json({ logs });
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
setInterval(() => {
  const now = new Date();
  
  couponRedemptions.forEach(r => {
    if (r.isActive && new Date(r.expiresAt) < now) {
      r.isActive = false;
      console.log(`[CLEANUP] Deactivated expired coupon: ${r.id}`);
    }
  });

  demoSessions.forEach(s => {
    if (s.isActive && new Date(s.expiresAt) < now) {
      s.isActive = false;
      console.log(`[CLEANUP] Deactivated expired demo: ${s.id}`);
    }
  });

  subscriptions.forEach(s => {
    if (s.isActive && new Date(s.expiresAt) < now) {
      s.isActive = false;
      console.log(`[CLEANUP] Deactivated expired subscription: ${s.id}`);
    }
  });

  resetCodes.forEach(rc => {
    if (!rc.used && new Date(rc.expiresAt) < now) {
      rc.used = true;
      console.log(`[CLEANUP] Expired reset code for: ${rc.email}`);
    }
  });
}, 60000);

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 YCKF Backend Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${NODE_ENV}`);
  console.log(`🌐 Listening on: 0.0.0.0:${PORT}`);
  console.log(`\n��� Default Users:`);
  console.log(`   Admin: admin@yckf.org / SecureAdmin@2024`);
  console.log(`   User:  user@yckf.org / TestUser@2024`);
  console.log(`\n��� Demo Token: DEMO-YCKF-2024`);
  console.log(`\n⚠️  Production checklist:`);
  console.log(`   ✓ Change JWT_SECRET`);
  console.log(`   ✓ Use real database`);
  console.log(`   ✓ Enable HTTPS`);
  console.log(`   ✓ Set up monitoring`);
  console.log(`   ✓ Configure email (EMAIL_USER and EMAIL_PASS in .env)\n`);
});

module.exports = app;
