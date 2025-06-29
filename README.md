# AdChute Backend API

Backend API service for AdChute DNS ad-blocking service.

## Features

- User authentication and registration
- JWT-based token management
- MongoDB integration for user and subscription data
- DNS server assignment and management
- Subscription validation
- Rate limiting and security middleware

## Environment Variables

Copy `.env.example` to `.env` and configure:

- `MONGODB_URI` - MongoDB connection string
- `JWT_SECRET` - Secret for access tokens
- `JWT_REFRESH_SECRET` - Secret for refresh tokens
- `STRIPE_SECRET_KEY` - Stripe API key for payments
- `PIHOLE_ADMIN_PASSWORD` - PiHole admin interface password

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - User logout
- `GET /api/auth/verify` - Verify token validity

### User Management
- `GET /api/user/profile` - Get user profile
- `GET /api/user/subscription-status` - Get subscription status
- `DELETE /api/user/account` - Delete user account

### DNS Management
- `GET /api/dns/server` - Get assigned DNS server
- `POST /api/dns/release` - Release DNS server assignment
- `GET /api/dns/validate-access` - Validate DNS access
- `GET /api/dns/servers/status` - Get all server status

## Development

```bash
npm install
npm run dev
```

## Production

```bash
npm install --only=production
npm start
```