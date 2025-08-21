# Writing Style Mimicry

A powerful AI-powered application that analyzes your writing style and generates content that matches your unique voice.

## 🚀 Features

- **Style Analysis**: Upload documents to analyze your unique writing patterns
- **Content Generation**: Generate text in your personal writing style
- **Document Management**: View, organize, and manage your writing samples
- **Secure Authentication**: JWT-based user authentication with bcrypt password hashing
- **Real-time Updates**: Live style analysis updates when documents are added/removed
- **Export & Share**: Copy generated content to clipboard

## 🛡️ Security Features

- **Rate Limiting**: Protection against brute force attacks
- **Input Validation**: Comprehensive sanitization of user inputs
- **XSS Protection**: HTML sanitization and safe DOM manipulation
- **Helmet Security**: HTTP security headers
- **Environment Variables**: Secure configuration management

## 📋 Prerequisites

- Node.js 16.0 or higher
- NPM or Yarn
- OpenAI API key

## 🔧 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd writing-style-mimicry-mvp
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your OpenAI API key
   ```

4. **Initialize the database**
   ```bash
   node setup.js
   ```

5. **Start the server**
   ```bash
   npm start
   ```

6. **Open your browser**
   Navigate to `http://localhost:3000`

## 🔑 Environment Variables

Create a `.env` file with the following variables:

```env
OPENAI_API_KEY=your-openai-api-key-here
JWT_SECRET=your-secure-random-jwt-secret
NODE_ENV=production
PORT=3000
```

## 🗄️ Database Schema

The application uses SQLite with the following tables:

- **users**: User accounts and authentication
- **writing_styles**: Analyzed writing styles
- **documents**: Uploaded documents and text samples
- **generated_content**: AI-generated content history

## 🔧 Configuration

Edit `config.js` to customize:

- File upload limits
- Database settings
- JWT token expiration
- API rate limits

## 📁 Project Structure

```
writing-style-mimicry-mvp/
├── public/
│   ├── dashboard.html    # Main application dashboard
│   └── login.html        # Authentication page
├── server.js             # Express server and API routes
├── config.js             # Application configuration
├── setup.js              # Database initialization
└── package.json          # Dependencies and scripts
```

## 🚀 Deployment

### Production Checklist

1. **Set strong JWT secret**
   ```bash
   export JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
   ```

2. **Configure environment**
   ```bash
   export NODE_ENV=production
   export OPENAI_API_KEY=your-production-api-key
   ```

3. **Update CORS settings** in `server.js` for your domain

4. **Use a reverse proxy** (nginx/Apache) in production

5. **Enable HTTPS** for secure token transmission

### Docker Deployment (Optional)

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

## 🔍 API Endpoints

### Authentication
- `POST /api/auth/register` - Create new account
- `POST /api/auth/login` - User login
- `GET /api/auth/verify` - Verify JWT token

### Writing Styles
- `GET /api/styles` - Get user's writing styles
- `POST /api/styles/analyze` - Create/update writing style
- `GET /api/styles/:id` - Get specific style with documents
- `DELETE /api/styles/:id` - Delete style and all related data

### Documents
- `GET /api/documents/:id/content` - View document content
- `DELETE /api/documents/:id` - Delete document (triggers re-analysis)

### Content Generation
- `POST /api/generate` - Generate content using saved style
- `GET /api/history` - Get generation history

## 🛠️ Development

### Running in Development

```bash
npm run dev  # Starts server with nodemon
```

### File Watching

The application uses `nodemon` for development with automatic restarts.

### Debugging

Enable debug logging:
```bash
DEBUG=* node server.js
```

## 📊 Monitoring & Logs

- Application logs are written to the console
- Rate limiting logs show blocked requests
- Database operations are logged for debugging

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:

1. Check the console logs for error messages
2. Verify your OpenAI API key is valid
3. Ensure all environment variables are set
4. Check file upload permissions

## 🔄 Changelog

### v1.0.0
- Initial release
- Style analysis and content generation
- User authentication and document management
- Security enhancements and rate limiting
- Production-ready deployment configuration

---

**Built with ❤️ using Node.js, Express, SQLite, and OpenAI GPT-4**
