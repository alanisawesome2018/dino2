const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const OpenAI = require('openai');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const config = require('./config');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize OpenAI
const openai = new OpenAI({
    apiKey: config.OPENAI_API_KEY
});

// FIXED CORS Configuration - Allow all origins in development
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        // In development, allow all origins
        // In production, you should restrict this to your actual domain
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:5500',
            'http://127.0.0.1:5500',
            'http://localhost:5173',  // Vite
            'http://127.0.0.1:5173',
            'http://localhost:3001',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:3001'
        ];
        
        // In development mode, allow all origins
        if (process.env.NODE_ENV !== 'production') {
            return callback(null, true);
        }
        
        // In production, check against whitelist
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Length', 'X-Request-Id']
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Add this BEFORE other middleware
app.options('*', cors(corsOptions)); // Enable preflight for all routes

// Other middleware
app.use(express.json());
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

    console.log('Database initialized successfully');
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

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
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

        // Extract text from all uploaded files
        const extractedTexts = [];
        for (const file of files) {
            const text = await extractTextFromFile(file);
            extractedTexts.push(text);

            // Save document to database
            await db.run(
                'INSERT INTO documents (user_id, style_id, filename, content, file_type) VALUES (?, ?, ?, ?, ?)',
                [req.user.id, styleId || null, file.originalname, text, path.extname(file.originalname)]
            );
        }

        console.log('Analyzing writing style...');
        
        // Analyze the writing style
        const styleAnalysis = await analyzeWritingStyle(extractedTexts);
        
        let style;
        if (styleId) {
            // Update existing style
            await db.run(
                'UPDATE writing_styles SET analysis = ?, sample_text = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                [styleAnalysis, extractedTexts[0].substring(0, 500), styleId, req.user.id]
            );
            style = await db.get('SELECT * FROM writing_styles WHERE id = ?', [styleId]);
        } else {
            // Create new style
            const result = await db.run(
                'INSERT INTO writing_styles (user_id, name, analysis, sample_text) VALUES (?, ?, ?, ?)',
                [req.user.id, styleName || 'My Writing Style', styleAnalysis, extractedTexts[0].substring(0, 500)]
            );
            style = await db.get('SELECT * FROM writing_styles WHERE id = ?', [result.lastID]);
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

// Delete a specific document
app.delete('/api/documents/:id', authenticateToken, async (req, res) => {
    try {
        const docId = req.params.id;
        const userId = req.user.id;
        
        // First check if the document belongs to the user
        const doc = await db.get(
            'SELECT * FROM documents WHERE id = ? AND user_id = ?',
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
        
        res.json({ success: true, message: 'Document removed successfully' });
    } catch (error) {
        console.error('Error deleting document:', error);
        res.status(500).json({ error: 'Failed to delete document' });
    }
});


// ===================== STATIC FILE ROUTES =====================

// Serve login page as default
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running', cors: 'enabled' });
});

// Start server
async function startServer() {
    await initializeDatabase();
    
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
        console.log('CORS is enabled for development');
        console.log('Make sure to update the OpenAI API key in config.js');
    });
}

startServer().catch(console.error);