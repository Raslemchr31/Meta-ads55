# Meta Ads Intelligence Platform

A comprehensive Facebook/Meta ads management and analytics platform built with Next.js 14, TypeScript, and modern web technologies.

## 🚀 Features

- **Homepage** - Clean, responsive landing page with status dashboard
- **Authentication** - NextAuth.js integration for secure user management
- **Dashboard** - Comprehensive analytics and campaign management interface
- **API Routes** - RESTful endpoints for Meta Ads data integration
- **Middleware** - Simplified request handling without external dependencies

## 🛠️ Tech Stack

- **Frontend**: Next.js 14, React 18, TypeScript
- **Styling**: Inline CSS (no external framework dependencies)
- **Authentication**: NextAuth.js
- **API**: Next.js API routes
- **Database**: Configurable (PostgreSQL/MySQL support)

## 🏃‍♂️ Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/Raslemchr31/Meta-ads55.git
   cd Meta-ads55
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

4. **Run the development server**
   ```bash
   npm run dev
   ```

5. **Open your browser**
   Navigate to [http://localhost:3000](http://localhost:3000)

## 📁 Project Structure

```
src/
├── app/
│   ├── api/          # API routes
│   ├── dashboard/    # Dashboard pages
│   ├── globals.css   # Global styles
│   ├── layout.tsx    # Root layout
│   └── page.tsx      # Homepage
├── components/       # Reusable React components
├── hooks/           # Custom React hooks
├── lib/             # Utility functions and configurations
└── middleware.ts    # Next.js middleware
```

## 🌟 Key Recent Fixes

- ✅ **Blank Page Issue**: Fixed homepage rendering by removing CSS conflicts
- ✅ **JavaScript Assets**: Resolved 500 errors preventing client-side hydration
- ✅ **Middleware**: Simplified to remove Redis dependencies causing compilation errors
- ✅ **Theme Conflicts**: Fixed dark/light theme CSS conflicts

## 🔧 Configuration

The application supports various configuration options through environment variables:

- `NEXTAUTH_URL` - Application URL
- `NEXTAUTH_SECRET` - NextAuth.js secret key
- `DATABASE_URL` - Database connection string (optional)
- `REDIS_URL` - Redis connection string (optional)

## 📱 Available Routes

- `/` - Homepage with system status
- `/auth/login` - Authentication page
- `/dashboard` - Main dashboard (requires authentication)
- `/api/health` - Health check endpoint
- `/api/meta/*` - Meta Ads API endpoints

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Repository**: [https://github.com/Raslemchr31/Meta-ads55](https://github.com/Raslemchr31/Meta-ads55)
- **Issues**: [https://github.com/Raslemchr31/Meta-ads55/issues](https://github.com/Raslemchr31/Meta-ads55/issues)

---

🤖 Generated with [Claude Code](https://claude.ai/code)