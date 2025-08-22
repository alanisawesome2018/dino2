const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const rtfParser = require('rtf-parser');
const OpenAI = require('openai');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const config = require('./config');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware - COMMENTED OUT FOR DEVELOPMENT
// if (process.env.NODE_ENV === 'production') {
//     // Strict security for production
//     app.use(helmet({
//         contentSecurityPolicy: {
//             directives: {
//                 defaultSrc: ["'self'"],
//                 styleSrc: ["'self'", "'unsafe-inline'"],
//                 scriptSrc: ["'self'"],
//                 imgSrc: ["'self'", "data:", "https:", "blob:"],
//                 fontSrc: ["'self'", "data:"],
//                 connectSrc: ["'self'", "https://api.openai.com"],
//                 objectSrc: ["'none'"],
//                 mediaSrc: ["'self'"],
//                 frameSrc: ["'none'"],
//             },
//         },
//         hsts: {
//             maxAge: 31536000,
//             includeSubDomains: true,
//             preload: true
//         }
//     }));
// } else {
//     // Relaxed security for development - no CSP restrictions
//     app.use(helmet({
//         contentSecurityPolicy: false, // Disable CSP entirely in development
//         crossOriginEmbedderPolicy: false,
//         hsts: false
//     }));
//     console.log('Development mode: CSP disabled for compatibility with inline scripts');
// }
console.log('Development mode: All security features disabled for development');

// Rate limiting - COMMENTED OUT FOR DEVELOPMENT
// const authLimiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 5, // 5 attempts per window
//     message: { error: 'Too many login attempts, please try again later' },
//     standardHeaders: true,
//     legacyHeaders: false,
// });

// const apiLimiter = rateLimit({
//     windowMs: 15 * 60 * 1000, // 15 minutes
//     max: 100, // 100 requests per window
//     message: { error: 'Too many requests, please try again later' },
//     standardHeaders: true,
//     legacyHeaders: false,
// });

// Apply rate limiting - COMMENTED OUT FOR DEVELOPMENT
// app.use('/api/auth', authLimiter);
// app.use('/api', apiLimiter);

// Initialize OpenAI
const openai = new OpenAI({
    apiKey: config.OPENAI_API_KEY
});

// Email Configuration
const emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'herodotus.ai666@gmail.com',
        pass: process.env.EMAIL_PASS || 'megq afht wnpv kikb'
    }
});

// Verify email connection (handle gracefully)
emailTransporter.verify((error, success) => {
    if (error) {
        console.log('⚠️  Email service not configured properly. Email features may not work.');
        console.log('   To fix: Set up Gmail App Password or configure different email service.');
    } else {
        console.log('📧 Email service ready and authenticated');
    }
});

// CORS Configuration - SIMPLIFIED FOR DEVELOPMENT
const corsOptions = {
    origin: true, // Allow all origins for development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Content-Length', 'X-Request-Id'],
    maxAge: 86400, // 24 hours
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Add this BEFORE other middleware
app.options('*', cors(corsOptions));

// Additional middleware - SECURITY HEADERS DISABLED FOR DEVELOPMENT
app.use(express.json({ limit: '50mb' })); // Increased limit for development
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Security headers - COMMENTED OUT FOR DEVELOPMENT
// app.use((req, res, next) => {
//     // Remove server header
//     res.removeHeader('X-Powered-By');
//     // Add custom security headers
//     res.setHeader('X-Content-Type-Options', 'nosniff');
//     res.setHeader('X-Frame-Options', 'DENY');
//     res.setHeader('X-XSS-Protection', '1; mode=block');
//     res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
//     next();
// });

// Static file serving
app.use(express.static('public'));

// Initialize Database
let db;

async function initializeDatabase() {
    db = await open({
        filename: './database.sqlite',
        driver: sqlite3.Database
    });

    // Create users table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            google_id TEXT,
            email_verified BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Add email_verified column if it doesn't exist (for existing databases)
    try {
        await db.exec(`ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE`);
    } catch (error) {
        // Column might already exist, ignore error
    }

    // Create writing_styles table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS writing_styles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            analysis TEXT NOT NULL,
            sample_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    `);

    // Create documents table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            style_id INTEGER,
            filename TEXT NOT NULL,
            content TEXT NOT NULL,
            file_type TEXT,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (style_id) REFERENCES writing_styles (id)
        )
    `);

    // Create generated_content table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS generated_content (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            style_id INTEGER,
            prompt TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (style_id) REFERENCES writing_styles (id)
        )
    `);

    // Create performance indexes for faster queries
    await db.exec(`
        CREATE INDEX IF NOT EXISTS idx_writing_styles_user_id ON writing_styles(user_id);
        CREATE INDEX IF NOT EXISTS idx_documents_style_id ON documents(style_id);
        CREATE INDEX IF NOT EXISTS idx_documents_user_id ON documents(user_id);
        CREATE INDEX IF NOT EXISTS idx_generated_content_style_id ON generated_content(style_id);
        CREATE INDEX IF NOT EXISTS idx_generated_content_user_id ON generated_content(user_id);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_writing_styles_created_at ON writing_styles(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_generated_content_created_at ON generated_content(created_at DESC);
    `);

    // Create metrics table for analytics
    await db.exec(`
        CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            metadata TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_metrics_event_type ON metrics(event_type);
        CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp DESC);
    `);

    // Create password reset tokens table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_password_reset_token ON password_reset_tokens(token);
        CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at);
    `);

    // Create email verification tokens table
    await db.exec(`
        CREATE TABLE IF NOT EXISTS email_verification_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at DATETIME NOT NULL,
            used BOOLEAN DEFAULT FALSE,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_email_verification_token ON email_verification_tokens(token);
        CREATE INDEX IF NOT EXISTS idx_email_verification_expires ON email_verification_tokens(expires_at);
    `);

    console.log('Database initialized successfully with performance indexes');
}

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

// JWT Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, config.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Input validation middleware
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email) && email.length <= 255;
}

function validatePassword(password) {
    return password && password.length >= 8 && password.length <= 128;
}

function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.trim().slice(0, 1000); // Limit length and trim
}

// Database backup function
async function createBackup() {
    try {
        const backupDir = path.join(__dirname, 'backups');
        if (!fsSync.existsSync(backupDir)) {
            fsSync.mkdirSync(backupDir);
        }
        
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = path.join(backupDir, `backup-${timestamp}.sqlite`);
        
        // Copy database file
        await fs.copyFile(path.join(__dirname, 'database.sqlite'), backupPath);
        
        // Keep only last 7 backups
        const backupFiles = (await fs.readdir(backupDir))
            .filter(file => file.startsWith('backup-') && file.endsWith('.sqlite'))
            .sort()
            .reverse();
        
        for (let i = 7; i < backupFiles.length; i++) {
            await fs.unlink(path.join(backupDir, backupFiles[i]));
        }
        
        console.log(`Database backup created: ${backupPath}`);
        return backupPath;
    } catch (error) {
        console.error('Backup failed:', error);
        throw error;
    }
}

// Schedule daily backups
function scheduleBackups() {
    const scheduleBackup = () => {
        createBackup().catch(console.error);
        setTimeout(scheduleBackup, 24 * 60 * 60 * 1000); // 24 hours
    };
    
    // Initial backup after 1 minute, then daily
    setTimeout(scheduleBackup, 60 * 1000);
}

// Metrics tracking function
async function trackMetric(eventType, userId = null, metadata = {}) {
    try {
        await db.run(
            'INSERT INTO metrics (event_type, user_id, metadata) VALUES (?, ?, ?)',
            eventType,
            userId,
            JSON.stringify(metadata)
        );
    } catch (error) {
        console.error('Failed to track metric:', error);
    }
}

// Helper function to extract text from various file types
async function extractTextFromFile(file) {
    const extension = path.extname(file.originalname).toLowerCase();
    
    try {
        switch (extension) {
            case '.txt':
                return file.buffer.toString('utf-8');
            
            case '.pdf':
                const pdfData = await pdfParse(file.buffer);
                return pdfData.text;
            
            case '.docx':
            case '.doc':
                const result = await mammoth.extractRawText({ buffer: file.buffer });
                return result.value;
            
            case '.rtf':
                const rtfData = file.buffer.toString('utf-8');
                try {
                    // rtf-parser usage: parse method returns a promise
                    const parsed = await new Promise((resolve, reject) => {
                        rtfParser.parseString(rtfData, (err, doc) => {
                            if (err) reject(err);
                            else resolve(doc);
                        });
                    });
                    return parsed.content || parsed.text || parsed.toString() || 'RTF content could not be extracted';
                } catch (rtfError) {
                    console.warn('RTF parsing failed, trying as plain text:', rtfError.message);
                    // Fallback: basic RTF text extraction
                    return rtfData.replace(/\\[a-z]+\d*\s?/gi, '').replace(/[{}]/g, '').trim();
                }
            
            default:
                throw new Error(`Unsupported file type: ${extension}`);
        }
    } catch (error) {
        console.error(`Error extracting text from ${file.originalname}:`, error);
        throw error;
    }
}

// Analyze writing style using OpenAI
async function analyzeWritingStyle(texts) {
    try {
        const combinedText = texts.join('\n\n---\n\n');
        
        const analysisPrompt = `Analyze the following text samples and identify the key writing style characteristics:

${combinedText}

Please identify:
1. Vocabulary preferences (formal/informal, technical/simple, specific word choices)
2. Sentence structure (short/long, simple/complex)
3. Tone and voice (professional/casual, serious/humorous, direct/indirect)
4. Grammar patterns and punctuation preferences
5. Common phrases or expressions
6. Paragraph structure and length preferences
7. Any unique stylistic elements

Provide a concise but comprehensive analysis that can be used to replicate this writing style.`;

        const response = await openai.chat.completions.create({
            model: 'gpt-4o-mini',  // Most cost-efficient model ($0.15/1M input, $0.60/1M output)
            messages: [
                {
                    role: 'system',
                    content: 'You are an expert linguist and writing style analyst.'
                },
                {
                    role: 'user',
                    content: analysisPrompt
                }
            ],
            temperature: 0.3,
            max_tokens: 1000
        });

        console.log('analyzing responses...');
        console.log(response.choices[0].message.content);
        return response.choices[0].message.content;
    } catch (error) {
        console.error('Error analyzing writing style:', error);
        
        // Check if it's an API key issue
        if (error.status === 401 || error.code === 'invalid_api_key') {
            console.error('🚨 API KEY AUTHENTICATION FAILED during style analysis 🚨');
            console.error('This is likely due to:');
            console.error('- API key has expired or been revoked');
            console.error('- API key usage quota exceeded');
            console.error('- Invalid API key format');
        }
        
        throw error;
    }
}

// Re-analyze a style after document changes
async function reanalyzeStyle(styleId, userId) {
    try {
        // Get all remaining documents for this style
        const documents = await db.all(
            'SELECT content FROM documents WHERE style_id = ? AND user_id = ?',
            [styleId, userId]
        );
        
        if (documents.length === 0) {
            // No documents left - clear the analysis but keep the style
            await db.run(
                'UPDATE writing_styles SET analysis = ?, sample_text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                ['No documents available for analysis. Please add documents to generate a writing style.', '', styleId, userId]
            );
            console.log(`Style ${styleId} cleared - no documents remaining (user must manually delete)`);
            return;
        }
        
        // Re-analyze with remaining documents
        const texts = documents.map(doc => doc.content);
        const newAnalysis = await analyzeWritingStyle(texts);
        
        // Update the style analysis
        await db.run(
            'UPDATE writing_styles SET analysis = ?, sample_text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
            [newAnalysis, texts[0].substring(0, 500), styleId, userId]
        );
        
        console.log(`Style ${styleId} re-analyzed with ${documents.length} remaining documents`);
    } catch (error) {
        console.error('Error re-analyzing style:', error);
        // Don't throw - document deletion should still succeed even if re-analysis fails
    }
}

// Generate content in the analyzed style
async function generateStyledContent(styleAnalysis, prompt) {
    try {
        const generationPrompt = `Based on the following writing style analysis:

${styleAnalysis}

Generate content for this request: "${prompt}"

Important: Match the identified writing style exactly, including vocabulary choices, sentence structure, tone, grammar patterns, and any unique stylistic elements. Make the generated content sound authentic to the analyzed style.`;

        const response = await openai.chat.completions.create({
            model: 'gpt-4o-mini',  // Most cost-efficient model
            messages: [
                {
                    role: 'system',
                    content: 'You are an expert writer who can perfectly mimic any writing style based on analysis.'
                },
                {
                    role: 'user',
                    content: generationPrompt
                }
            ],
            temperature: 0.7,
            max_tokens: 1000
        });

        return response.choices[0].message.content;
    } catch (error) {
        console.error('Error generating styled content:', error);
        
        // Check if it's an API key issue
        if (error.status === 401 || error.code === 'invalid_api_key') {
            console.error('🚨 API KEY AUTHENTICATION FAILED during content generation 🚨');
            console.error('This is likely due to:');
            console.error('- API key has expired or been revoked');
            console.error('- API key usage quota exceeded');
            console.error('- Invalid API key format');
        }
        
        throw error;
    }
}

// ===================== AUTH ROUTES =====================

// Register endpoint
app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Password must be 8-128 characters long' });
        }

        // Check if user exists
        const existingUser = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user (email_verified defaults to FALSE)
        const result = await db.run(
            'INSERT INTO users (email, password, email_verified) VALUES (?, ?, ?)',
            [email, hashedPassword, false]
        );

        const userId = result.lastID;

        // Generate email verification token
        const verificationToken = require('crypto').randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 3600000); // 24 hours from now

        // Store verification token
        await db.run(
            'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            [userId, verificationToken, expiresAt.toISOString()]
        );

        // Send verification email
        const verificationUrl = `http://localhost:3000/verify-email.html?token=${verificationToken}`;
        
        const mailOptions = {
            from: 'herodotus.ai666@gmail.com',
            to: email,
            subject: 'Verify Your Email - Herodotus',
            html: `
                <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #667eea; text-align: center;">Welcome to Herodotus!</h2>
                    <p>Thank you for creating an account with Herodotus, your personal AI writing assistant.</p>
                    <p>To get started, please verify your email address by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationUrl}" style="display: inline-block; padding: 15px 30px; background-color: #667eea; color: white; text-decoration: none; border-radius: 8px; font-weight: 500;">Verify Email Address</a>
                    </div>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">${verificationUrl}</p>
                    <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
                        This verification link will expire in 24 hours. If you didn't create this account, please ignore this email.
                    </p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                    <p style="font-size: 0.8em; color: #999; text-align: center;">
                        Herodotus - Your Personal AI Writing Assistant<br>
                        Need help? Contact us at alancai888888@gmail.com
                    </p>
                </div>
            `
        };

        try {
            await emailTransporter.sendMail(mailOptions);
            console.log(`✅ Verification email sent to: ${email}`);
            
            res.json({
                success: true,
                message: 'Account created successfully! Please check your email to verify your account before logging in.',
                email: email
            });
        } catch (emailError) {
            console.error('❌ Failed to send verification email:', emailError);
            
            // Log the verification URL to console since email failed
            const verificationUrl = `http://localhost:3000/verify-email.html?token=${verificationToken}`;
            console.log('\n=== EMAIL VERIFICATION TOKEN (EMAIL FAILED) ===');
            console.log(`Verification URL: ${verificationUrl}`);
            console.log('===============================================\n');
            
            res.json({
                success: true,
                message: 'Account created successfully! However, there was an issue sending the verification email. Please check the server console for the verification link.',
                email: email
            });
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        // Find user
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check if email is verified
        if (!user.email_verified) {
            return res.status(401).json({ 
                error: 'Please verify your email address before logging in. Check your email for a verification link.',
                needsVerification: true
            });
        }

        // Create JWT token
        const tokenPayload = {
            id: user.id,
            email: user.email
        };
        const token = jwt.sign(tokenPayload, config.JWT_SECRET || 'default-secret-key', { expiresIn: '7d' });

        res.json({
            success: true,
            token,
            user: tokenPayload
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Verify token endpoint
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ===================== PASSWORD RESET ROUTES =====================

// Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        // Find user by email
        const user = await db.get('SELECT id, email FROM users WHERE email = ?', [email]);
        
        if (!user) {
            // Don't reveal if email exists or not for security
            return res.json({ success: true, message: 'If an account with that email exists, we have sent a password reset link.' });
        }

        // Generate reset token
        const resetToken = require('crypto').randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

        // Store reset token in database
        await db.run(
            'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            [user.id, resetToken, expiresAt.toISOString()]
        );

        // Send email (for development, just log the token)
        const resetUrl = `http://localhost:3000/reset-password.html?token=${resetToken}`;
        
        try {
            const mailOptions = {
                from: 'herodotus.ai666@gmail.com',
                to: email,
                subject: 'Password Reset - Herodotus',
                html: `
                    <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                        <h2 style="color: #667eea;">Password Reset Request</h2>
                        <p>You requested a password reset for your Herodotus account.</p>
                        <p>Click the button below to reset your password:</p>
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetUrl}" style="display: inline-block; padding: 15px 30px; background-color: #667eea; color: white; text-decoration: none; border-radius: 8px; font-weight: 500;">Reset Password</a>
                        </div>
                        <p>Or copy and paste this link in your browser:</p>
                        <p style="word-break: break-all; color: #667eea;">${resetUrl}</p>
                        <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
                            This link will expire in 1 hour. If you didn't request this, please ignore this email.
                        </p>
                    </div>
                `
            };

            await emailTransporter.sendMail(mailOptions);
            console.log(`📧 Password reset email sent to: ${email}`);
        } catch (emailError) {
            console.error('❌ Failed to send password reset email:', emailError);
            // In development, log the reset URL as fallback
            console.log('\n=== PASSWORD RESET TOKEN (EMAIL FAILED) ===');
            console.log(`Reset URL: ${resetUrl}`);
            console.log('==========================================\n');
        }

        res.json({ success: true, message: 'If an account with that email exists, we have sent a password reset link.' });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to process password reset request' });
    }
});

// Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        
        if (!token || !password) {
            return res.status(400).json({ error: 'Token and password are required' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        // Find valid reset token
        const resetRecord = await db.get(`
            SELECT rt.id, rt.user_id, rt.expires_at, rt.used, u.email 
            FROM password_reset_tokens rt 
            JOIN users u ON rt.user_id = u.id 
            WHERE rt.token = ? AND rt.used = 0
        `, [token]);

        if (!resetRecord) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }

        // Check if token is expired
        if (new Date() > new Date(resetRecord.expires_at)) {
            return res.status(400).json({ error: 'Reset token has expired' });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user password
        await db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, resetRecord.user_id]);

        // Mark token as used
        await db.run('UPDATE password_reset_tokens SET used = 1 WHERE id = ?', [resetRecord.id]);

        // Track metric
        await trackMetric('password_reset_completed', resetRecord.user_id);

        res.json({ success: true, message: 'Password has been reset successfully' });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// Email verification endpoint
app.get('/api/auth/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        
        if (!token) {
            return res.status(400).json({ error: 'Verification token is required' });
        }

        // Find valid verification token
        const verificationRecord = await db.get(`
            SELECT vt.id, vt.user_id, vt.expires_at, vt.used, u.email 
            FROM email_verification_tokens vt 
            JOIN users u ON vt.user_id = u.id 
            WHERE vt.token = ? AND vt.used = 0
        `, [token]);

        if (!verificationRecord) {
            return res.status(400).json({ error: 'Invalid or expired verification token' });
        }

        // Check if token is expired
        if (new Date() > new Date(verificationRecord.expires_at)) {
            return res.status(400).json({ error: 'Verification token has expired' });
        }

        // Mark user as verified
        await db.run('UPDATE users SET email_verified = 1 WHERE id = ?', [verificationRecord.user_id]);

        // Mark token as used
        await db.run('UPDATE email_verification_tokens SET used = 1 WHERE id = ?', [verificationRecord.id]);

        // Track metric
        await trackMetric('email_verified', verificationRecord.user_id);

        res.json({ success: true, message: 'Email verified successfully! You can now log in.' });
    } catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ error: 'Failed to verify email' });
    }
});

// Resend verification email endpoint
app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        // Find user
        const user = await db.get('SELECT id, email, email_verified FROM users WHERE email = ?', [email]);
        
        if (!user) {
            // Don't reveal if email exists or not for security
            return res.json({ success: true, message: 'If an account with that email exists and is unverified, we have sent a new verification email.' });
        }

        if (user.email_verified) {
            return res.json({ success: true, message: 'Email is already verified. You can log in.' });
        }

        // Generate new verification token
        const verificationToken = require('crypto').randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 24 * 3600000); // 24 hours from now

        // Store new verification token (and mark old ones as used)
        await db.run('UPDATE email_verification_tokens SET used = 1 WHERE user_id = ?', [user.id]);
        await db.run(
            'INSERT INTO email_verification_tokens (user_id, token, expires_at) VALUES (?, ?, ?)',
            [user.id, verificationToken, expiresAt.toISOString()]
        );

        // Send verification email
        const verificationUrl = `http://localhost:3000/verify-email.html?token=${verificationToken}`;
        
        const mailOptions = {
            from: 'herodotus.ai666@gmail.com',
            to: email,
            subject: 'Verify Your Email - Herodotus',
            html: `
                <div style="max-width: 600px; margin: 0 auto; font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2 style="color: #667eea; text-align: center;">Email Verification - Herodotus</h2>
                    <p>You requested a new verification email for your Herodotus account.</p>
                    <p>Please verify your email address by clicking the button below:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${verificationUrl}" style="display: inline-block; padding: 15px 30px; background-color: #667eea; color: white; text-decoration: none; border-radius: 8px; font-weight: 500;">Verify Email Address</a>
                    </div>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #667eea;">${verificationUrl}</p>
                    <p style="margin-top: 30px; font-size: 0.9em; color: #666;">
                        This verification link will expire in 24 hours. If you didn't request this, please ignore this email.
                    </p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                    <p style="font-size: 0.8em; color: #999; text-align: center;">
                        Herodotus - Your Personal AI Writing Assistant<br>
                        Need help? Contact us at alancai888888@gmail.com
                    </p>
                </div>
            `
        };

        try {
            await emailTransporter.sendMail(mailOptions);
            console.log(`New verification email sent to: ${email}`);
        } catch (emailError) {
            console.error('Failed to send verification email:', emailError);
            return res.status(500).json({ error: 'Failed to send verification email' });
        }

        res.json({ success: true, message: 'If an account with that email exists and is unverified, we have sent a new verification email.' });
    } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({ error: 'Failed to resend verification email' });
    }
});

// ===================== WRITING STYLE ROUTES =====================

// Get user's writing styles
app.get('/api/styles', authenticateToken, async (req, res) => {
    try {
        const styles = await db.all(
            'SELECT * FROM writing_styles WHERE user_id = ? ORDER BY created_at DESC',
            [req.user.id]
        );
        res.json(styles);
    } catch (error) {
        console.error('Error fetching styles:', error);
        res.status(500).json({ error: 'Failed to fetch writing styles' });
    }
});

// Get specific writing style
app.get('/api/styles/:id', authenticateToken, async (req, res) => {
    try {
        const style = await db.get(
            'SELECT * FROM writing_styles WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );
        
        if (!style) {
            return res.status(404).json({ error: 'Style not found' });
        }

        // Get associated documents
        const documents = await db.all(
            'SELECT * FROM documents WHERE style_id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );

        res.json({ ...style, documents });
    } catch (error) {
        console.error('Error fetching style:', error);
        res.status(500).json({ error: 'Failed to fetch writing style' });
    }
});

// Create or update writing style
app.post('/api/styles/analyze', authenticateToken, upload.array('files', 10), async (req, res) => {
    try {
        const { styleName, styleId } = req.body;
        const files = req.files;

        if (!files || files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        console.log(`Processing ${files.length} files for style analysis...`);
        
        // Track style creation attempt
        await trackMetric('style_creation_started', req.user.userId, { 
            file_count: files.length, 
            style_name: styleName 
        });

        // Extract text from all uploaded files
        const extractedTexts = [];
        const fileDetails = []; // Store file details for later database insertion
        for (const file of files) {
            const text = await extractTextFromFile(file);
            extractedTexts.push(text);
            
            // Store file details for later insertion (after we have style_id)
            fileDetails.push({
                filename: file.originalname,
                content: text,
                fileType: path.extname(file.originalname)
            });
        }

        console.log('Analyzing writing style...');
        
        // Analyze the writing style
        const styleAnalysis = await analyzeWritingStyle(extractedTexts);
        
        let style;
        let finalStyleId;
        
        if (styleId) {
            // Update existing style
            await db.run(
                'UPDATE writing_styles SET analysis = ?, sample_text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                [styleAnalysis, extractedTexts[0].substring(0, 500), styleId, req.user.id]
            );
            style = await db.get('SELECT * FROM writing_styles WHERE id = ?', [styleId]);
            finalStyleId = styleId;
        } else {
            // Create new style first
            const result = await db.run(
                'INSERT INTO writing_styles (user_id, name, analysis, sample_text) VALUES (?, ?, ?, ?)',
                [req.user.id, styleName || 'My Writing Style', styleAnalysis, extractedTexts[0].substring(0, 500)]
            );
            style = await db.get('SELECT * FROM writing_styles WHERE id = ?', [result.lastID]);
            finalStyleId = result.lastID;
        }
        
        // Now save documents with the correct style_id
        for (const fileDetail of fileDetails) {
            await db.run(
                'INSERT INTO documents (user_id, style_id, filename, content, file_type) VALUES (?, ?, ?, ?, ?)',
                [req.user.id, finalStyleId, fileDetail.filename, fileDetail.content, fileDetail.fileType]
            );
        }

        res.json({
            success: true,
            style,
            message: 'Writing style analyzed and saved successfully'
        });

    } catch (error) {
        console.error('Error in style analysis:', error);
        res.status(500).json({
            error: error.message || 'An error occurred during style analysis'
        });
    }
});

// Delete writing style
app.delete('/api/styles/:id', authenticateToken, async (req, res) => {
    try {
        // Delete associated documents first
        await db.run('DELETE FROM documents WHERE style_id = ? AND user_id = ?', [req.params.id, req.user.id]);
        await db.run('DELETE FROM generated_content WHERE style_id = ? AND user_id = ?', [req.params.id, req.user.id]);
        
        // Delete the style
        const result = await db.run(
            'DELETE FROM writing_styles WHERE id = ? AND user_id = ?',
            [req.params.id, req.user.id]
        );

        if (result.changes === 0) {
            return res.status(404).json({ error: 'Style not found' });
        }

        res.json({ success: true, message: 'Style deleted successfully' });
    } catch (error) {
        console.error('Error deleting style:', error);
        res.status(500).json({ error: 'Failed to delete style' });
    }
});

// ===================== CONTENT GENERATION ROUTES =====================

// Generate content using saved style
app.post('/api/generate', authenticateToken, async (req, res) => {
    try {
        const { prompt, styleId } = req.body;

        if (!prompt) {
            return res.status(400).json({ error: 'No prompt provided' });
        }

        let styleAnalysis;
        
        if (styleId) {
            // Use saved style
            const style = await db.get(
                'SELECT * FROM writing_styles WHERE id = ? AND user_id = ?',
                [styleId, req.user.id]
            );
            
            if (!style) {
                return res.status(404).json({ error: 'Style not found' });
            }
            
            styleAnalysis = style.analysis;
        } else {
            return res.status(400).json({ error: 'Please select a writing style' });
        }

        console.log('Generating styled content...');
        
        // Generate content in the analyzed style
        const generatedContent = await generateStyledContent(styleAnalysis, prompt);

        // Save generated content
        await db.run(
            'INSERT INTO generated_content (user_id, style_id, prompt, content) VALUES (?, ?, ?, ?)',
            [req.user.id, styleId, prompt, generatedContent]
        );

        res.json({
            success: true,
            content: generatedContent
        });

    } catch (error) {
        console.error('Error in content generation:', error);
        
        // Check if it's an API key issue
        if (error.status === 401 || error.code === 'invalid_api_key') {
            console.error('🚨 API KEY AUTHENTICATION FAILED 🚨');
            console.error('This is likely due to:');
            console.error('- API key has expired or been revoked');
            console.error('- API key usage quota exceeded');
            console.error('- Invalid API key format');
            console.error('Please check your OpenAI account and generate a new API key');
            
            res.status(500).json({
                error: 'Content generation failed - API authentication issue. Please contact support.'
            });
        } else {
            res.status(500).json({
                error: error.message || 'An error occurred during content generation'
            });
        }
    }
});

// Generate content with uploaded files (one-time use)
app.post('/api/generate/quick', authenticateToken, upload.array('files', 10), async (req, res) => {
    try {
        const { prompt } = req.body;
        const files = req.files;

        if (!files || files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        if (!prompt) {
            return res.status(400).json({ error: 'No prompt provided' });
        }

        console.log(`Processing ${files.length} files for quick generation...`);

        // Extract text from all uploaded files
        const extractedTexts = await Promise.all(
            files.map(file => extractTextFromFile(file))
        );

        console.log('Analyzing writing style...');
        
        // Analyze the writing style
        const styleAnalysis = await analyzeWritingStyle(extractedTexts);
        
        console.log('Generating styled content...');
        
        // Generate content in the analyzed style
        const generatedContent = await generateStyledContent(styleAnalysis, prompt);

        res.json({
            success: true,
            content: generatedContent,
            styleAnalysis: styleAnalysis
        });

    } catch (error) {
        console.error('Error in quick generation:', error);
        res.status(500).json({
            error: error.message || 'An error occurred during processing'
        });
    }
});

// Get user's generated content history
app.get('/api/history', authenticateToken, async (req, res) => {
    try {
        const history = await db.all(
            `SELECT gc.*, ws.name as style_name 
             FROM generated_content gc 
             LEFT JOIN writing_styles ws ON gc.style_id = ws.id 
             WHERE gc.user_id = ? 
             ORDER BY gc.created_at DESC 
             LIMIT 50`,
            [req.user.id]
        );
        res.json(history);
    } catch (error) {
        console.error('Error fetching history:', error);
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// Style-specific history endpoint to prevent content mixing
app.get('/api/styles/:id/history', authenticateToken, async (req, res) => {
    try {
        const styleId = parseInt(req.params.id);
        
        // Verify style belongs to user
        const style = await db.get(
            'SELECT id FROM writing_styles WHERE id = ? AND user_id = ?',
            [styleId, req.user.id]
        );
        
        if (!style) {
            return res.status(404).json({ error: 'Style not found' });
        }
        
        const history = await db.all(
            `SELECT gc.*, ws.name as style_name 
             FROM generated_content gc 
             LEFT JOIN writing_styles ws ON gc.style_id = ws.id 
             WHERE gc.style_id = ? AND gc.user_id = ? 
             ORDER BY gc.created_at DESC 
             LIMIT 50`,
            [styleId, req.user.id]
        );
        
        console.log(`📊 Style ${styleId} history: ${history.length} items`);
        res.json(history);
    } catch (error) {
        console.error('Error fetching style history:', error);
        res.status(500).json({ error: 'Failed to fetch style history' });
    }
});

// ===================== USER PROFILE ROUTES =====================

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const user = await db.get(
            'SELECT id, email, created_at FROM users WHERE id = ?',
            [req.user.id]
        );
        
        const stats = await db.get(
            `SELECT 
                (SELECT COUNT(*) FROM writing_styles WHERE user_id = ?) as styles_count,
                (SELECT COUNT(*) FROM documents WHERE user_id = ?) as documents_count,
                (SELECT COUNT(*) FROM generated_content WHERE user_id = ?) as generations_count`,
            [req.user.id, req.user.id, req.user.id]
        );

        res.json({ ...user, ...stats });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

// Update password
app.post('/api/user/password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current and new password required' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }

        const user = await db.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
        
        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.run(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, req.user.id]
        );

        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ error: 'Failed to update password' });
    }
});

// ===================== DOCUMENT ROUTES =====================

// Get document content
app.get('/api/documents/:id/content', authenticateToken, async (req, res) => {
    try {
        const docId = req.params.id;
        const userId = req.user.id;
        
        // Get document content
        const doc = await db.get(
            'SELECT filename, content FROM documents WHERE id = ? AND user_id = ?',
            [docId, userId]
        );
        
        if (!doc) {
            return res.status(404).json({ error: 'Document not found' });
        }
        
        res.json({ 
            filename: doc.filename,
            content: doc.content 
        });
    } catch (error) {
        console.error('Error fetching document content:', error);
        res.status(500).json({ error: 'Failed to fetch document content' });
    }
});

// Delete a specific document
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const docId = req.params.id;
        const userId = req.user.id;
        
        // First check if the document belongs to the user and get style_id
        const doc = await db.get(
            'SELECT style_id FROM documents WHERE id = ? AND user_id = ?',
            [docId, userId]
        );
        
        if (!doc) {
            return res.status(404).json({ error: 'Document not found or unauthorized' });
        }
        
        // Delete the document
        await db.run(
            'DELETE FROM documents WHERE id = ? AND user_id = ?',
            [docId, userId]
        );
        
        // Re-analyze the style if there are remaining documents
        if (doc.style_id) {
            await reanalyzeStyle(doc.style_id, userId);
        }
        
        res.json({ success: true, message: 'Document removed successfully' });
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({ error: 'Failed to delete document' });
    }
});

// Delete generated content
app.delete('/api/content/:id', authenticateToken, async (req, res) => {
    try {
        const contentId = req.params.id;
        const userId = req.user.id;
        
        // Check if content belongs to user
        const content = await db.get(
            'SELECT * FROM generated_content WHERE id = ? AND user_id = ?',
            [contentId, userId]
        );
        
        if (!content) {
            return res.status(404).json({ error: 'Generated content not found or unauthorized' });
        }
        
        // Delete the generated content
        await db.run(
            'DELETE FROM generated_content WHERE id = ? AND user_id = ?',
            [contentId, userId]
        );
        
        await trackMetric('content_deleted', userId, {
            content_id: contentId,
            style_id: content.style_id
        });
        
        res.json({ success: true, message: 'Generated content deleted successfully' });
    } catch (error) {
        console.error('Error deleting generated content:', error);
        res.status(500).json({ error: 'Failed to delete generated content' });
    }
});


// ===================== STATIC FILE ROUTES =====================

// Serve login page as default
// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

// API key validation endpoint
app.get('/api/validate-key', async (req, res) => {
    try {
        // Simple test with minimal tokens to check API key validity
        const response = await openai.chat.completions.create({
            model: 'gpt-4o-mini',
            messages: [{ role: 'user', content: 'Test' }],
            max_tokens: 5
        });
        
        res.json({
            status: 'valid',
            message: 'API key is working',
            model: 'gpt-4o-mini'
        });
    } catch (error) {
        console.error('API key validation failed:', error);
        
        if (error.status === 401 || error.code === 'invalid_api_key') {
            res.status(401).json({
                status: 'invalid',
                message: 'API key is invalid or expired',
                error: error.message
            });
        } else {
            res.status(500).json({
                status: 'error',
                message: 'Unable to validate API key',
                error: error.message
            });
        }
    }
});

// Developer metrics endpoint
app.get('/api/metrics', async (req, res) => {
    try {
        const { timeframe = '7d', limit = 100 } = req.query;
        
        // Calculate date range
        const now = new Date();
        const timeframes = {
            '1h': new Date(now - 60 * 60 * 1000),
            '24h': new Date(now - 24 * 60 * 60 * 1000),
            '7d': new Date(now - 7 * 24 * 60 * 60 * 1000),
            '30d': new Date(now - 30 * 24 * 60 * 60 * 1000)
        };
        const since = timeframes[timeframe] || timeframes['7d'];
        
        // Get metrics summary
        const eventCounts = await db.all(`
            SELECT event_type, COUNT(*) as count 
            FROM metrics 
            WHERE timestamp >= ? 
            GROUP BY event_type 
            ORDER BY count DESC
        `, since.toISOString());
        
        // Get recent events
        const recentEvents = await db.all(`
            SELECT event_type, user_id, metadata, timestamp 
            FROM metrics 
            WHERE timestamp >= ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        `, since.toISOString(), parseInt(limit));
        
        // Get user stats
        const userStats = await db.get(`
            SELECT 
                COUNT(DISTINCT id) as total_users,
                COUNT(CASE WHEN created_at >= ? THEN 1 END) as new_users
            FROM users
        `, since.toISOString());
        
        // Get style stats
        const styleStats = await db.get(`
            SELECT 
                COUNT(*) as total_styles,
                COUNT(CASE WHEN created_at >= ? THEN 1 END) as new_styles
            FROM writing_styles
        `, since.toISOString());
        
        res.json({
            timeframe,
            since: since.toISOString(),
            summary: {
                users: userStats,
                styles: styleStats,
                events: eventCounts
            },
            recent_events: recentEvents
        });
        
    } catch (error) {
        console.error('Error fetching metrics:', error);
        res.status(500).json({ error: 'Failed to fetch metrics' });
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve dashboard page
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Start server
async function startServer() {
    await initializeDatabase();
    
    // Enhanced error logging
    function logError(error, context = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            error: {
                message: error.message,
                stack: error.stack,
                name: error.name
            },
            context
        };
        
        console.error('ERROR:', JSON.stringify(logEntry, null, 2));
        
        // Write to error log file
        const logDir = path.join(__dirname, 'logs');
        if (!fsSync.existsSync(logDir)) {
            fsSync.mkdirSync(logDir);
        }
        
        const logFile = path.join(logDir, `error-${new Date().toISOString().split('T')[0]}.log`);
        fsSync.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    }

    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
        console.log('CORS is enabled for development');
        console.log('Make sure to update the OpenAI API key in config.js');
        
        // Start backup scheduler
        scheduleBackups();
        console.log('Database backup scheduler started');
    });
}

startServer().catch(console.error);