# Artist Tiwari — Ecommerce + Customer Accounts

## Current features
- Premium handmade-art storefront
- Admin login with JWT + bcrypt
- Admin product CRUD and stock management
- Customer registration/login with hashed passwords
- Customer account dashboard and server-side order history
- Login required before checkout
- Server-side price and inventory validation
- COD confirmation
- Razorpay test/live integration hooks with signature verification and webhook support
- Helmet, CORS and rate limiting
- JSON storage for local development

## Start locally
1. Extract the ZIP with `package.json` at the project root.
2. Make sure Node.js 18+ is installed.
3. Run `npm install` (first run only).
4. Run `npm start` or `start.bat`.
5. Open `http://localhost:3001/`.

Do not open HTML files with `file:///`; the Express server must serve the site.

## Customer
- Create an account at `/customer-register.html`.
- Sign in at `/customer-login.html`.
- Account dashboard: `/account.html`.
- Checkout requires a customer account.

## Admin
- Login: `/admin-login.html`
- Default development credentials are controlled by `.env`; change them before production.

## Production checklist
Before taking real orders, move products/orders/customers to a real database, use cloud/object image storage, configure HTTPS + a custom domain, switch Razorpay to live keys, configure the Razorpay webhook, create backups, configure shipping/email notifications, and set production secrets.


## Customer accounts
Customers can create an account at `/customer-register.html` and sign in at `/customer-login.html`.
Checkout requires a signed-in customer. Customer sessions use JWTs and passwords are stored as bcrypt hashes.
The account page is `/account.html`.

## Home hero background fix
The home-page hero artwork background has been restored. Helmet CSP explicitly permits the configured Unsplash image host and Razorpay checkout resources. Inline checkout/admin scripts were moved to external JS files so CSP does not silently block them.

## Netlify + Render deployment

For the live split deployment, see `DEPLOY-NOW.md`. The `_redirects` file proxies Netlify `/api/*` requests to the Render Node/Express backend. Update the Render hostname there if your Render service URL differs from `https://artist-tiwari-api.onrender.com`.
