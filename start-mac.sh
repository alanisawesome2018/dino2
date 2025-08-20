#!/bin/bash

# Writing Style Mimicry - macOS Start Script
# Optimized for macOS systems

set -e  # Exit on error

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                                                          ║"
echo "║     Writing Style Mimicry - macOS Setup                 ║"
echo "║     Your Personal AI Writing Assistant                  ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to check if running on macOS
check_macos() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        echo -e "${RED}[✗] This script is designed for macOS${NC}"
        echo "Please use start.js instead: node start.js"
        exit 1
    fi
    echo -e "${GREEN}[✓]${NC} Running on macOS"
}

# Function to check Node.js
check_node() {
    if command -v node >/dev/null 2>&1; then
        NODE_VERSION=$(node -v)
        echo -e "${GREEN}[✓]${NC} Node.js $NODE_VERSION installed"
        
        # Check version is 14+
        MAJOR=$(echo $NODE_VERSION | cut -d. -f1 | sed 's/v//')
        if [ $MAJOR -lt 14 ]; then
            echo -e "${YELLOW}[!]${NC} Node.js version is old. Recommended: v14+"
        fi
    else
        echo -e "${RED}[✗]${NC} Node.js not found"
        echo ""
        echo "Install Node.js using one of these methods:"
        echo "1. Download from https://nodejs.org/"
        echo "2. Using Homebrew: brew install node"
        exit 1
    fi
}

# Function to fix encoding issues
fix_encoding() {
    echo -e "${BLUE}[*]${NC} Checking for encoding issues..."
    
    # Run the diagnostic script if it exists
    if [ -f "fix-issues.js" ]; then
        node fix-issues.js
    else
        # Manual fixes for common issues
        if [ -f "public/dashboard.html" ]; then
            # Fix the multiplication sign issue
            sed -i '' 's/Ã—/×/g' public/dashboard.html 2>/dev/null || true
        fi
    fi
}

# Function to create directories
create_directories() {
    echo -e "${BLUE}[*]${NC} Creating project directories..."
    mkdir -p public uploads logs
    echo -e "${GREEN}[✓]${NC} Directories ready"
}

# Function to check required files
check_files() {
    echo -e "${BLUE}[*]${NC} Checking required files..."
    
    MISSING=""
    [ ! -f "server.js" ] && MISSING="$MISSING server.js"
    [ ! -f "config.js" ] && MISSING="$MISSING config.js"
    [ ! -f "package.json" ] && MISSING="$MISSING package.json"
    
    if [ ! -z "$MISSING" ]; then
        echo -e "${RED}[✗]${NC} Missing files:$MISSING"
        echo "Please ensure all project files are present"
        exit 1
    fi
    
    echo -e "${GREEN}[✓]${NC} All required files found"
}

# Function to check/configure API key
configure_api_key() {
    if grep -q "your-openai-api-key-here" config.js 2>/dev/null; then
        echo -e "${YELLOW}[!]${NC} OpenAI API key not configured"
        echo ""
        echo "Enter your OpenAI API key (or press Enter to skip):"
        read -s API_KEY
        
        if [ ! -z "$API_KEY" ]; then
            # Backup config
            cp config.js config.js.backup
            
            # Update API key
            sed -i '' "s/your-openai-api-key-here/$API_KEY/g" config.js
            echo -e "${GREEN}[✓]${NC} API key configured"
        else
            echo -e "${YELLOW}[!]${NC} Skipping - remember to update config.js"
        fi
    else
        echo -e "${GREEN}[✓]${NC} API key configured"
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${BLUE}[*]${NC} Checking npm dependencies..."
    
    if [ -d "node_modules" ]; then
        # Quick check if main dependencies exist
        if [ -d "node_modules/express" ] && [ -d "node_modules/openai" ]; then
            echo -e "${GREEN}[✓]${NC} Dependencies installed"
        else
            echo -e "${YELLOW}[!]${NC} Reinstalling dependencies..."
            rm -rf node_modules package-lock.json
            npm install
        fi
    else
        echo -e "${BLUE}[*]${NC} Installing dependencies..."
        npm install
    fi
}

# Function to setup database
setup_database() {
    if [ -f "database.sqlite" ]; then
        echo -e "${GREEN}[✓]${NC} Database exists"
    else
        echo -e "${BLUE}[*]${NC} Creating database..."
        
        # Create setup.js if it doesn't exist
        if [ ! -f "setup.js" ]; then
            node -e "
            const sqlite3 = require('sqlite3').verbose();
            const db = new sqlite3.Database('database.sqlite');
            
            db.serialize(() => {
                // Create tables
                db.run(\`CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    google_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )\`);
                
                db.run(\`CREATE TABLE IF NOT EXISTS writing_styles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    analysis TEXT NOT NULL,
                    sample_text TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )\`);
                
                db.run(\`CREATE TABLE IF NOT EXISTS documents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    style_id INTEGER,
                    filename TEXT NOT NULL,
                    content TEXT NOT NULL,
                    file_type TEXT,
                    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (style_id) REFERENCES writing_styles (id)
                )\`);
                
                db.run(\`CREATE TABLE IF NOT EXISTS generated_content (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    style_id INTEGER,
                    prompt TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id),
                    FOREIGN KEY (style_id) REFERENCES writing_styles (id)
                )\`);
            });
            
            db.close(() => {
                console.log('Database created successfully');
                process.exit(0);
            });
            " 2>/dev/null || echo -e "${YELLOW}[!]${NC} Database setup completed"
        else
            echo n | node setup.js 2>/dev/null || true
        fi
        
        echo -e "${GREEN}[✓]${NC} Database ready"
    fi
}

# Function to check port
check_port() {
    PORT=${1:-3000}
    
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}[!]${NC} Port $PORT is in use"
        
        # Try to identify the process
        PROCESS=$(lsof -i :$PORT | grep LISTEN | awk '{print $1}' | head -1)
        echo "Process using port: $PROCESS"
        
        echo ""
        echo "Options:"
        echo "1) Kill the process and continue"
        echo "2) Use a different port"
        echo "3) Exit"
        echo -n "Choice (1-3): "
        read CHOICE
        
        case $CHOICE in
            1)
                lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
                sleep 1
                echo -e "${GREEN}[✓]${NC} Port cleared"
                ;;
            2)
                echo -n "Enter port number: "
                read NEW_PORT
                export PORT=$NEW_PORT
                ;;
            3)
                exit 0
                ;;
        esac
    else
        echo -e "${GREEN}[✓]${NC} Port $PORT available"
    fi
}

# Function to start server
start_server() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✨ Setup complete! Starting server...${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${CYAN}➜${NC} Local:    http://localhost:${PORT:-3000}"
    echo -e "  ${CYAN}➜${NC} Network:  http://$(ipconfig getifaddr en0 2>/dev/null || echo localhost):${PORT:-3000}"
    echo ""
    echo -e "  ${YELLOW}Demo Account:${NC}"
    echo "  Email: demo@example.com"
    echo "  Password: demo1234"
    echo ""
    echo -e "  ${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    # Check for nodemon
    if command -v nodemon >/dev/null 2>&1; then
        echo -e "${BLUE}[*]${NC} Starting with auto-reload (development mode)..."
        npx nodemon server.js
    else
        echo -e "${BLUE}[*]${NC} Starting server..."
        node server.js
    fi
}

# Main execution
main() {
    check_macos
    check_node
    fix_encoding
    create_directories
    check_files
    configure_api_key
    install_dependencies
    setup_database
    check_port
    start_server
}

# Trap Ctrl+C
trap 'echo ""; echo -e "${YELLOW}[!]${NC} Server stopped"; exit 0' INT

# Run main function
main