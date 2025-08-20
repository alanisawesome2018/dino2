#!/usr/bin/env node

/**
 * Diagnostic and Fix Script for Writing Style Mimicry
 * This script identifies and fixes common issues
 */

const fs = require('fs');
const path = require('path');

// ANSI color codes
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m'
};

console.log(`${colors.blue}==================================${colors.reset}`);
console.log(`${colors.magenta}Writing Style Mimicry - Diagnostic Tool${colors.reset}`);
console.log(`${colors.blue}==================================${colors.reset}\n`);

let issuesFound = 0;
let issuesFixed = 0;

// 1. Check for encoding issues in HTML files
function checkAndFixHTML() {
    console.log(`${colors.yellow}[1] Checking HTML files for encoding issues...${colors.reset}`);
    
    const htmlFiles = [
        'public/dashboard.html',
        'public/login.html',
        'public/index.html'
    ];
    
    htmlFiles.forEach(filePath => {
        if (fs.existsSync(filePath)) {
            let content = fs.readFileSync(filePath, 'utf8');
            let originalContent = content;
            
            // Fix common encoding issues
            const fixes = [
                { find: /Ã—/g, replace: '×' },  // Fix multiplication sign
                { find: /â€™/g, replace: "'" },  // Fix apostrophe
                { find: /â€œ/g, replace: '"' },  // Fix left quote
                { find: /â€/g, replace: '"' },   // Fix right quote
                { find: /â€"/g, replace: '—' },  // Fix em dash
                { find: /â€"/g, replace: '–' },  // Fix en dash
                { find: /Â°/g, replace: '°' },   // Fix degree symbol
                { find: /Â·/g, replace: '·' },   // Fix middle dot
                { find: /â€¦/g, replace: '...' } // Fix ellipsis
            ];
            
            fixes.forEach(fix => {
                if (content.match(fix.find)) {
                    content = content.replace(fix.find, fix.replace);
                    issuesFound++;
                    console.log(`  ${colors.red}✗ Found encoding issue in ${filePath}${colors.reset}`);
                }
            });
            
            if (content !== originalContent) {
                fs.writeFileSync(filePath, content, 'utf8');
                issuesFixed++;
                console.log(`  ${colors.green}✓ Fixed encoding issues in ${filePath}${colors.reset}`);
            } else {
                console.log(`  ${colors.green}✓ ${filePath} is clean${colors.reset}`);
            }
        }
    });
}

// 2. Check server.js for syntax errors
function checkServerJS() {
    console.log(`\n${colors.yellow}[2] Checking server.js for syntax errors...${colors.reset}`);
    
    if (!fs.existsSync('server.js')) {
        console.log(`  ${colors.red}✗ server.js not found!${colors.reset}`);
        issuesFound++;
        return;
    }
    
    try {
        const content = fs.readFileSync('server.js', 'utf8');
        
        // Check for common issues
        if (content.includes('res.status(500)') && !content.includes('res.status(500).json')) {
            console.log(`  ${colors.red}✗ Found incomplete res.status() call${colors.reset}`);
            issuesFound++;
            
            // Fix it
            let fixedContent = content.replace(
                /res\.status\(500\)(?!\.)/g,
                'res.status(500).json({ error: "Internal server error" })'
            );
            
            fs.writeFileSync('server.js', fixedContent, 'utf8');
            issuesFixed++;
            console.log(`  ${colors.green}✓ Fixed incomplete status calls${colors.reset}`);
        }
        
        // Try to parse as JavaScript
        try {
            new Function(content);
            console.log(`  ${colors.green}✓ server.js syntax appears valid${colors.reset}`);
        } catch (e) {
            console.log(`  ${colors.red}✗ Syntax error in server.js: ${e.message}${colors.reset}`);
            issuesFound++;
        }
        
    } catch (error) {
        console.log(`  ${colors.red}✗ Error reading server.js: ${error.message}${colors.reset}`);
        issuesFound++;
    }
}

// 3. Check for missing dependencies
function checkDependencies() {
    console.log(`\n${colors.yellow}[3] Checking dependencies...${colors.reset}`);
    
    if (!fs.existsSync('package.json')) {
        console.log(`  ${colors.red}✗ package.json not found!${colors.reset}`);
        issuesFound++;
        return;
    }
    
    try {
        const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
        const requiredDeps = [
            'express',
            'multer',
            'cors',
            'openai',
            'pdf-parse',
            'mammoth',
            'bcrypt',
            'jsonwebtoken',
            'sqlite3',
            'sqlite'
        ];
        
        const missingDeps = requiredDeps.filter(dep => 
            !packageJson.dependencies || !packageJson.dependencies[dep]
        );
        
        if (missingDeps.length > 0) {
            console.log(`  ${colors.red}✗ Missing dependencies: ${missingDeps.join(', ')}${colors.reset}`);
            issuesFound++;
            
            // Add missing dependencies
            if (!packageJson.dependencies) packageJson.dependencies = {};
            
            const depVersions = {
                'express': '^4.18.2',
                'multer': '^1.4.5-lts.1',
                'cors': '^2.8.5',
                'openai': '^4.20.0',
                'pdf-parse': '^1.1.1',
                'mammoth': '^1.6.0',
                'bcrypt': '^5.1.1',
                'jsonwebtoken': '^9.0.2',
                'sqlite3': '^5.1.6',
                'sqlite': '^5.1.1'
            };
            
            missingDeps.forEach(dep => {
                packageJson.dependencies[dep] = depVersions[dep];
            });
            
            fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2), 'utf8');
            issuesFixed++;
            console.log(`  ${colors.green}✓ Added missing dependencies to package.json${colors.reset}`);
            console.log(`  ${colors.yellow}! Run 'npm install' to install them${colors.reset}`);
        } else {
            console.log(`  ${colors.green}✓ All required dependencies are listed${colors.reset}`);
        }
        
        // Check if node_modules exists
        if (!fs.existsSync('node_modules')) {
            console.log(`  ${colors.yellow}! node_modules not found - run 'npm install'${colors.reset}`);
            issuesFound++;
        }
        
    } catch (error) {
        console.log(`  ${colors.red}✗ Error checking package.json: ${error.message}${colors.reset}`);
        issuesFound++;
    }
}

// 4. Check file structure
function checkFileStructure() {
    console.log(`\n${colors.yellow}[4] Checking file structure...${colors.reset}`);
    
    const requiredDirs = ['public', 'uploads', 'logs'];
    const requiredFiles = [
        'server.js',
        'config.js',
        'package.json',
        'public/login.html',
        'public/dashboard.html'
    ];
    
    requiredDirs.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
            console.log(`  ${colors.green}✓ Created missing directory: ${dir}${colors.reset}`);
            issuesFixed++;
        } else {
            console.log(`  ${colors.green}✓ Directory exists: ${dir}${colors.reset}`);
        }
    });
    
    requiredFiles.forEach(file => {
        if (!fs.existsSync(file)) {
            console.log(`  ${colors.red}✗ Missing file: ${file}${colors.reset}`);
            issuesFound++;
        } else {
            console.log(`  ${colors.green}✓ File exists: ${file}${colors.reset}`);
        }
    });
}

// 5. Check config.js
function checkConfig() {
    console.log(`\n${colors.yellow}[5] Checking configuration...${colors.reset}`);
    
    if (!fs.existsSync('config.js')) {
        console.log(`  ${colors.red}✗ config.js not found!${colors.reset}`);
        
        // Create a basic config.js
        const configContent = `// Configuration file for API keys and sensitive data
// IMPORTANT: Never commit this file to version control with real API keys

module.exports = {
    // Replace this with your actual OpenAI API key
    OPENAI_API_KEY: 'your-openai-api-key-here',
    
    // JWT Secret for authentication
    JWT_SECRET: 'your-super-secret-jwt-key-change-this-in-production',
    
    // Server configuration
    PORT: 3000,
    MAX_FILE_SIZE: 10 * 1024 * 1024, // 10MB
    MAX_FILES: 10,
    
    // Database
    DATABASE_PATH: './database.sqlite'
};`;
        
        fs.writeFileSync('config.js', configContent, 'utf8');
        console.log(`  ${colors.green}✓ Created config.js${colors.reset}`);
        issuesFixed++;
    } else {
        const config = fs.readFileSync('config.js', 'utf8');
        if (config.includes('your-openai-api-key-here')) {
            console.log(`  ${colors.yellow}! OpenAI API key not configured${colors.reset}`);
            issuesFound++;
        } else {
            console.log(`  ${colors.green}✓ config.js exists and has API key${colors.reset}`);
        }
    }
}

// 6. Fix dashboard.html specific issues
function fixDashboardHTML() {
    console.log(`\n${colors.yellow}[6] Fixing dashboard.html specific issues...${colors.reset}`);
    
    const dashboardPath = 'public/dashboard.html';
    
    if (fs.existsSync(dashboardPath)) {
        let content = fs.readFileSync(dashboardPath, 'utf8');
        let originalContent = content;
        
        // Fix the specific close button issue
        content = content.replace(/Ã—/g, '×');
        
        // Fix the style name parameter in the body
        content = content.replace(
            'formData.append(\'name\', styleName);',
            'formData.append(\'styleName\', styleName);'
        );
        
        // Ensure proper escaping in copyToClipboard
        content = content.replace(
            /onclick="copyToClipboard\('([^']*)'\)"/g,
            (match, p1) => {
                const escaped = p1.replace(/'/g, "\\'").replace(/"/g, '\\"');
                return `onclick="copyToClipboard(\`${escaped}\`)"`;
            }
        );
        
        if (content !== originalContent) {
            fs.writeFileSync(dashboardPath, content, 'utf8');
            console.log(`  ${colors.green}✓ Fixed dashboard.html issues${colors.reset}`);
            issuesFixed++;
        } else {
            console.log(`  ${colors.green}✓ dashboard.html appears correct${colors.reset}`);
        }
    }
}

// Run all checks
console.log('Starting diagnostic checks...\n');

checkAndFixHTML();
checkServerJS();
checkDependencies();
checkFileStructure();
checkConfig();
fixDashboardHTML();

// Summary
console.log(`\n${colors.blue}==================================${colors.reset}`);
console.log(`${colors.magenta}Diagnostic Summary${colors.reset}`);
console.log(`${colors.blue}==================================${colors.reset}`);
console.log(`Issues found: ${issuesFound}`);
console.log(`Issues fixed: ${issuesFixed}`);

if (issuesFound > issuesFixed) {
    console.log(`\n${colors.yellow}Some issues require manual intervention:${colors.reset}`);
    console.log('1. Run: npm install');
    console.log('2. Add your OpenAI API key to config.js');
    console.log('3. Run: node start.js');
} else if (issuesFound === 0) {
    console.log(`\n${colors.green}✓ Everything looks good! You can run: node start.js${colors.reset}`);
} else {
    console.log(`\n${colors.green}✓ All issues have been fixed! Next steps:${colors.reset}`);
    console.log('1. Run: npm install');
    console.log('2. Add your OpenAI API key to config.js');
    console.log('3. Run: node start.js');
}

process.exit(0);