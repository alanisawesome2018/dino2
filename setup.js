// Setup script to initialize the database and create necessary tables
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const path = require('path');

async function setup() {
    console.log('🚀 Setting up Writing Style Mimicry database...\n');

    try {
        // Open database connection
        const db = await open({
            filename: path.join(__dirname, 'database.sqlite'),
            driver: sqlite3.Database
        });

        console.log('📊 Creating database tables...');

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
        console.log('✅ Users table created');

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
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        `);
        console.log('✅ Writing styles table created');

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
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (style_id) REFERENCES writing_styles (id) ON DELETE SET NULL
            )
        `);
        console.log('✅ Documents table created');

        // Create generated_content table
        await db.exec(`
            CREATE TABLE IF NOT EXISTS generated_content (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                style_id INTEGER,
                prompt TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (style_id) REFERENCES writing_styles (id) ON DELETE SET NULL
            )
        `);
        console.log('✅ Generated content table created');

        // Create indexes for better performance
        await db.exec(`
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_writing_styles_user ON writing_styles(user_id);
            CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
            CREATE INDEX IF NOT EXISTS idx_documents_style ON documents(style_id);
            CREATE INDEX IF NOT EXISTS idx_generated_content_user ON generated_content(user_id);
            CREATE INDEX IF NOT EXISTS idx_generated_content_style ON generated_content(style_id);
        `);
        console.log('✅ Database indexes created');

        // Optional: Create a demo user
        const createDemoUser = await promptUser('\nWould you like to create a demo user? (y/n): ');
        
        if (createDemoUser.toLowerCase() === 'y') {
            const email = 'demo@example.com';
            const password = 'demo1234';
            const hashedPassword = await bcrypt.hash(password, 10);
            
            try {
                await db.run(
                    'INSERT INTO users (email, password) VALUES (?, ?)',
                    [email, hashedPassword]
                );
                console.log(`\n✅ Demo user created:`);
                console.log(`   Email: ${email}`);
                console.log(`   Password: ${password}`);
            } catch (error) {
                if (error.code === 'SQLITE_CONSTRAINT') {
                    console.log('\n⚠️  Demo user already exists');
                } else {
                    throw error;
                }
            }
        }

        await db.close();
        
        console.log('\n🎉 Setup complete! Your database is ready.');
        console.log('\n📝 Next steps:');
        console.log('1. Update your OpenAI API key in config.js');
        console.log('2. Run "npm start" to start the server');
        console.log('3. Open http://localhost:3000 in your browser');
        
    } catch (error) {
        console.error('\n❌ Setup failed:', error);
        process.exit(1);
    }
}

function promptUser(question) {
    const readline = require('readline');
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        rl.question(question, (answer) => {
            rl.close();
            resolve(answer);
        });
    });
}

// Run setup
setup();