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

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware - conditional based on environment
if (process.env.NODE_ENV === 'production') {
    // Strict security for production
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                scriptSrc: ["'self'"],
                imgSrc: ["'self'", "data:", "https:", "blob:"],
                fontSrc: ["'self'", "data:"],
                connectSrc: ["'self'", "https://api.openai.com"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true
        }
    }));
} else {
    // Relaxed security for development - no CSP restrictions
    app.use(helmet({
        contentSecurityPolicy: false, // Disable CSP entirely in development
        crossOriginEmbedderPolicy: false,
        hsts: false
    }));
    console.log('Development mode: CSP disabled for compatibility with inline scripts');
}

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 attempts per window
    message: { error: 'Too many login attempts, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
    message: { error: 'Too many requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Apply rate limiting
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// Initialize OpenAI
const openai = new OpenAI({
    apiKey: config.OPENAI_API_KEY
});

// Secure CORS Configuration
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://localhost:3000',
            'http://127.0.0.1:3000',
            'http://localhost:5500', // Live Server
            'http://127.0.0.1:5500',
            'http://localhost:5173', // Vite
            'http://127.0.0.1:5173',
            // Add your production domain here when deploying
        ];
        
        // In development mode, allow all localhost/127.0.0.1 origins
        if (process.env.NODE_ENV !== 'production') {
            if (origin.includes('localhost') || origin.includes('127.0.0.1')) {
                return callback(null, true);
            }
        }
        
        // Check against whitelist
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.log(`CORS blocked origin: ${origin}`);
            callback(new Error('Not allowed by CORS'));
        }
    },
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

// Additional security middleware
app.use(express.json({ limit: '10mb' })); // Limit JSON payload size
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security headers
app.use((req, res, next) => {
    // Remove server header
    res.removeHeader('X-Powered-By');
    // Add custom security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

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
                    const parsed = rtfParser.parseString(rtfData);
                    return parsed.content || parsed.text || 'RTF content could not be extracted';
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

        // Create user
        const result = await db.run(
            'INSERT INTO users (email, password) VALUES (?, ?)',
            [email, hashedPassword]
        );

        const user = {
            id: result.lastID,
            email: email
        };

        // Create JWT token
        const token = jwt.sign(user, config.JWT_SECRET || 'default-secret-key', { expiresIn: '7d' });

        res.json({
            success: true,
            token,
            user
        });
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
        res.status(500).json({
            error: error.message || 'An error occurred during content generation'
        });
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

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running', cors: 'enabled' });
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