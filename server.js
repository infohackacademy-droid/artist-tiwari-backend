require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const PRODUCTS_FILE = path.join(DATA_DIR, "products.json");
const ORDERS_FILE = path.join(DATA_DIR, "orders.json");
const CUSTOMERS_FILE = path.join(DATA_DIR, "customers.json");
const JWT_SECRET = process.env.JWT_SECRET || (process.env.NODE_ENV === "production" ? "" : crypto.randomBytes(48).toString("hex"));
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "admin@artisttiwari.com").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "");
const ADMIN_PASSWORD_HASH = ADMIN_PASSWORD ? bcrypt.hashSync(ADMIN_PASSWORD, 12) : "";

fs.mkdirSync(DATA_DIR, { recursive: true });
function ensureJson(file, fallback) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(fallback, null, 2));
}
ensureJson(PRODUCTS_FILE, []);
ensureJson(ORDERS_FILE, []);
ensureJson(CUSTOMERS_FILE, []);

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); } catch { return []; }
}
function writeJson(file, value) {
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}
function cleanText(v, max = 500) { return String(v ?? "").trim().slice(0, max); }
function makeId(prefix = "AT") { return `${prefix}-${Date.now()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`; }
function money(n) { return Number.isFinite(Number(n)) ? Number(n) : 0; }
function shippingFor(subtotal) { return subtotal >= 5000 ? 0 : 199; }
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

if (process.env.NODE_ENV === "production" && (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12)) {
  console.error("Production configuration error: JWT_SECRET must be 32+ chars and ADMIN_PASSWORD must be 12+ chars.");
  process.exit(1);
}

const allowedOrigins = process.env.CORS_ORIGIN
  ? process.env.CORS_ORIGIN.split(",").map(s => s.trim()).filter(Boolean)
  : [];

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginResourcePolicy: false,
  contentSecurityPolicy: false
}));

// CSP is set manually so it works reliably across Helmet versions.
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; " +
    "script-src 'self' https://checkout.razorpay.com; " +
    "connect-src 'self' https://checkout.razorpay.com https://api.razorpay.com; " +
    "img-src 'self' data: blob: https://images.unsplash.com https://images.pexels.com https://*.unsplash.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; " +
    "frame-src 'self' https://api.razorpay.com https://checkout.razorpay.com"
  );
  next();
});
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Order-Token", "X-Razorpay-Signature"]
}));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 180, standardHeaders: true, legacyHeaders: false });
app.use("/api/", apiLimiter);
app.use("/api/auth/login", authLimiter);

app.use("/api/payments/webhook", express.raw({ type: "application/json", limit: "1mb" }));
app.use(express.json({ limit: "10mb" }));

function signAdminToken() {
  return jwt.sign({ sub: "admin", role: "admin", email: ADMIN_EMAIL }, JWT_SECRET, { expiresIn: "8h", issuer: "artist-tiwari" });
}
function signCustomerToken(customer) {
  return jwt.sign({ sub: customer.id, role: "customer", email: customer.email }, JWT_SECRET, { expiresIn: "30d", issuer: "artist-tiwari-customers" });
}
function requireCustomer(req, res, next) {
  if (!JWT_SECRET) return res.status(503).json({ error: "Server authentication is not configured." });
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Customer login required." });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "artist-tiwari-customers" });
    if (payload.role !== "customer") throw new Error("Invalid role");
    const customer = readJson(CUSTOMERS_FILE).find(c => c.id === payload.sub && c.active !== false);
    if (!customer) throw new Error("Customer not found");
    req.customer = customer;
    next();
  } catch { return res.status(401).json({ error: "Customer session expired. Please log in again." }); }
}

function requireAdmin(req, res, next) {
  if (!JWT_SECRET) return res.status(503).json({ error: "Server authentication is not configured." });
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ error: "Admin login required." });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "artist-tiwari" });
    if (payload.role !== "admin") throw new Error("Invalid role");
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Admin session expired. Please log in again." });
  }
}

function issueOrderToken(orderId) {
  return jwt.sign({ sub: orderId, type: "order" }, JWT_SECRET, { expiresIn: "90d", issuer: "artist-tiwari-orders" });
}
function requireOrderAccess(req, res, next) {
  const token = String(req.headers["x-order-token"] || "");
  if (!token) return res.status(401).json({ error: "Order access token required." });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "artist-tiwari-orders" });
    if (payload.type !== "order" || payload.sub !== req.params.id) throw new Error("Invalid order token");
    req.orderAccess = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired order access token." });
  }
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "Artist Tiwari API", authConfigured: Boolean(JWT_SECRET && ADMIN_PASSWORD), razorpayConfigured: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET), storage: "json-dev", time: new Date().toISOString() });
});

/* ---------------- AUTH ---------------- */
app.post("/api/auth/login", (req, res) => {
  const email = cleanText(req.body?.email, 160).toLowerCase();
  const password = String(req.body?.password || "");
  if (!ADMIN_PASSWORD) return res.status(503).json({ error: "Admin password is not configured. Set ADMIN_PASSWORD in .env." });
  if (email !== ADMIN_EMAIL || !bcrypt.compareSync(password, ADMIN_PASSWORD_HASH)) {
    return res.status(401).json({ error: "Invalid email or password." });
  }
  res.json({ token: signAdminToken(), user: { email: ADMIN_EMAIL, role: "admin" } });
});
app.get("/api/auth/me", requireAdmin, (req, res) => res.json({ user: { email: req.admin.email, role: req.admin.role } }));

/* ---------------- CUSTOMER AUTH ---------------- */
function publicCustomer(c) { return { id:c.id, name:c.name, email:c.email, phone:c.phone, createdAt:c.createdAt }; }
function validEmail(email) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
function validPhone(phone) { return /^[6-9]\d{9}$/.test(phone); }

app.post("/api/customer/register", authLimiter, (req,res) => {
  const name=cleanText(req.body?.name,120), email=cleanText(req.body?.email,160).toLowerCase(), phone=cleanText(req.body?.phone,20), password=String(req.body?.password||"");
  if(name.length<2) return res.status(400).json({error:"Please enter your full name."});
  if(!validEmail(email)) return res.status(400).json({error:"Please enter a valid email address."});
  if(!validPhone(phone)) return res.status(400).json({error:"Please enter a valid 10-digit Indian mobile number."});
  if(password.length<8 || password.length>128) return res.status(400).json({error:"Password must be 8 to 128 characters."});
  const customers=readJson(CUSTOMERS_FILE);
  if(customers.some(c=>c.email===email)) return res.status(409).json({error:"An account with this email already exists."});
  const customer={id:makeId("CUS"),name,email,phone,passwordHash:bcrypt.hashSync(password,12),createdAt:new Date().toISOString(),active:true};
  customers.push(customer); writeJson(CUSTOMERS_FILE,customers);
  res.status(201).json({token:signCustomerToken(customer),user:publicCustomer(customer)});
});

app.post("/api/customer/login", authLimiter, (req,res) => {
  const email=cleanText(req.body?.email,160).toLowerCase(), password=String(req.body?.password||"");
  const customer=readJson(CUSTOMERS_FILE).find(c=>c.email===email && c.active!==false);
  if(!customer || !customer.passwordHash || !bcrypt.compareSync(password,customer.passwordHash)) return res.status(401).json({error:"Invalid email or password."});
  res.json({token:signCustomerToken(customer),user:publicCustomer(customer)});
});

app.get("/api/customer/me", requireCustomer, (req,res) => {
  const orders=readJson(ORDERS_FILE).filter(o=>o.customerId===req.customer.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
  res.json({user:publicCustomer(req.customer),orders});
});

app.get("/api/customer/orders", requireCustomer, (req,res) => {
  res.json(readJson(ORDERS_FILE).filter(o=>o.customerId===req.customer.id).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt)));
});

/* ---------------- PRODUCTS ---------------- */
function normalizeProduct(p, old = {}) {
  return {
    id: cleanText(p.id, 100) || old.id || `painting-${Date.now()}-${crypto.randomBytes(3).toString("hex")}`,
    name: cleanText(p.name, 150) || old.name || "Untitled Artwork",
    category: cleanText(p.category, 80) || old.category || "Artwork",
    price: Math.max(0, money(p.price ?? old.price)),
    stock: Math.max(0, Math.floor(money(p.stock ?? old.stock))),
    medium: cleanText(p.medium ?? old.medium, 150),
    size: cleanText(p.size ?? old.size, 100),
    surface: cleanText(p.surface ?? old.surface, 100),
    image: cleanText(p.image ?? old.image, 2000000),
    description: cleanText(p.description ?? old.description, 3000),
    createdAt: old.createdAt || p.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

app.get("/api/products", (req, res) => res.json(readJson(PRODUCTS_FILE)));

app.post("/api/products/sync", requireAdmin, (req, res) => {
  const incoming = Array.isArray(req.body?.products) ? req.body.products : [];
  const normalized = incoming.map(p => normalizeProduct(p));
  writeJson(PRODUCTS_FILE, normalized);
  res.json({ ok: true, products: normalized });
});

app.post("/api/products", requireAdmin, (req, res) => {
  const p = req.body || {};
  if (!cleanText(p.name, 150)) return res.status(400).json({ error: "Product name is required." });
  const products = readJson(PRODUCTS_FILE);
  const product = normalizeProduct(p);
  if (products.some(x => x.id === product.id)) return res.status(409).json({ error: "Product ID already exists." });
  products.push(product);
  writeJson(PRODUCTS_FILE, products);
  res.status(201).json(product);
});

app.put("/api/products/:id", requireAdmin, (req, res) => {
  const products = readJson(PRODUCTS_FILE);
  const index = products.findIndex(p => String(p.id) === String(req.params.id));
  if (index < 0) return res.status(404).json({ error: "Product not found." });
  products[index] = normalizeProduct(req.body || {}, products[index]);
  writeJson(PRODUCTS_FILE, products);
  res.json(products[index]);
});

app.delete("/api/products/:id", requireAdmin, (req, res) => {
  const products = readJson(PRODUCTS_FILE);
  const next = products.filter(p => String(p.id) !== String(req.params.id));
  if (next.length === products.length) return res.status(404).json({ error: "Product not found." });
  writeJson(PRODUCTS_FILE, next);
  res.json({ ok: true });
});

/* ---------------- ORDERS ---------------- */
function buildOrderFromCart(body, customer = null) {
  const cart = Array.isArray(body.items) ? body.items : [];
  if (!cart.length) throw new Error("Cart is empty.");
  const products = readJson(PRODUCTS_FILE);
  const items = [];
  let subtotal = 0;
  for (const requested of cart) {
    const product = products.find(p => String(p.id) === String(requested.id));
    const quantity = Math.max(1, Math.min(50, Math.floor(money(requested.quantity ?? requested.qty ?? 1))));
    if (!product) throw new Error(`Artwork is unavailable.`);
    if (product.stock < quantity) throw new Error(`"${product.name}" has only ${product.stock} item(s) in stock.`);
    const price = money(product.price);
    items.push({ id: product.id, name: product.name, category: product.category || "Artwork", price, quantity, image: product.image || "" });
    subtotal += price * quantity;
  }
  const customerName = cleanText(customer?.name || body.customer?.name, 120);
  const phone = cleanText(customer?.phone || body.customer?.phone, 20);
  const email = cleanText(customer?.email || body.customer?.email, 160);
  const pin = cleanText(body.address?.pin, 10);
  if (!customerName || !/^[6-9]\d{9}$/.test(phone) || !cleanText(body.address?.address, 500) || !cleanText(body.address?.city, 100) || !cleanText(body.address?.state, 100) || !/^\d{6}$/.test(pin)) throw new Error("Please provide valid customer and delivery details.");
  const shipping = shippingFor(subtotal);
  return { id: makeId("AT"), customerId: customer?.id || null, createdAt: new Date().toISOString(), status: "Pending", paymentMethod: cleanText(body.paymentMethod, 30), paymentStatus: "Pending", subtotal, shipping, total: subtotal + shipping, customer: { name: customerName, phone, email }, address: { address: cleanText(body.address?.address, 500), city: cleanText(body.address?.city, 100), state: cleanText(body.address?.state, 100), pin }, items, stockDeducted: false };
}

app.post("/api/orders", (req, res) => {
  try {
    let customer = null;
    const header = String(req.headers.authorization || "");
    if (header.startsWith("Bearer ")) {
      try {
        const payload = jwt.verify(header.slice(7), JWT_SECRET, { issuer: "artist-tiwari-customers" });
        if (payload.role === "customer") customer = readJson(CUSTOMERS_FILE).find(c=>c.id===payload.sub && c.active!==false) || null;
      } catch {}
    }
    if (!customer) return res.status(401).json({error:"Please sign in to place an order."});
    if (!["UPI", "Card", "Net Banking", "COD"].includes(req.body?.paymentMethod)) return res.status(400).json({ error: "Invalid payment method." });
    const order = buildOrderFromCart(req.body || {}, customer);
    const orders = readJson(ORDERS_FILE);
    orders.push(order);
    writeJson(ORDERS_FILE, orders);
    res.status(201).json({ ...order, accessToken: issueOrderToken(order.id) });
  } catch (e) { res.status(400).json({ error: e.message || "Unable to create order." }); }
});

app.get("/api/orders", requireAdmin, (req, res) => res.json(readJson(ORDERS_FILE).sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))));

app.get("/api/orders/:id", requireOrderAccess, (req, res) => {
  const order = readJson(ORDERS_FILE).find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: "Order not found." });
  res.json(order);
});

app.put("/api/orders/:id/status", requireAdmin, (req, res) => {
  const allowed = ["Pending", "Processing", "Shipped", "Delivered", "Cancelled"];
  const status = cleanText(req.body?.status, 30);
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid order status." });
  const orders = readJson(ORDERS_FILE);
  const index = orders.findIndex(o => o.id === req.params.id);
  if (index < 0) return res.status(404).json({ error: "Order not found." });
  orders[index].status = status;
  orders[index].updatedAt = new Date().toISOString();
  writeJson(ORDERS_FILE, orders);
  res.json(orders[index]);
});

function deductStock(order) {
  if (order.stockDeducted) return true;
  const products = readJson(PRODUCTS_FILE);
  for (const item of order.items) {
    const p = products.find(x => String(x.id) === String(item.id));
    if (!p || Number(p.stock || 0) < Number(item.quantity || 1)) return false;
  }
  for (const item of order.items) {
    const p = products.find(x => String(x.id) === String(item.id));
    p.stock = Math.max(0, Number(p.stock || 0) - Number(item.quantity || 1));
  }
  writeJson(PRODUCTS_FILE, products);
  order.stockDeducted = true;
  return true;
}

app.post("/api/orders/:id/cod-confirm", (req, res) => {
  try {
    const orders = readJson(ORDERS_FILE);
    const order = orders.find(o => o.id === req.params.id);
    if (!order) return res.status(404).json({ error: "Order not found." });
    if (order.paymentMethod !== "COD") return res.status(400).json({ error: "This is not a COD order." });
    if (!deductStock(order)) return res.status(409).json({ error: "Stock changed. Please try again." });
    order.status = "Processing";
    order.updatedAt = new Date().toISOString();
    writeJson(ORDERS_FILE, orders);
    res.json({ ...order, accessToken: issueOrderToken(order.id) });
  } catch (e) { res.status(500).json({ error: "Unable to confirm COD order." }); }
});

/* ---------------- RAZORPAY ---------------- */
async function razorpayRequest(endpoint, method = "GET", body) {
  const key = process.env.RAZORPAY_KEY_ID, secret = process.env.RAZORPAY_KEY_SECRET;
  if (!key || !secret) throw new Error("Razorpay keys are not configured. Add them to .env.");
  const auth = Buffer.from(`${key}:${secret}`).toString("base64");
  const response = await fetch(`https://api.razorpay.com/v1/${endpoint}`, { method, headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data?.error?.description || "Razorpay API request failed.");
  return data;
}

app.post("/api/payments/create-order", requireOrderAccess, async (req, res) => {
  try {
    const localOrderId = cleanText(req.body?.orderId, 100);
    const orders = readJson(ORDERS_FILE);
    const order = orders.find(o => o.id === localOrderId);
    if (!order) return res.status(404).json({ error: "Local order not found." });
    if (order.paymentMethod === "COD") return res.status(400).json({ error: "COD does not require online payment." });
    const rp = await razorpayRequest("orders", "POST", { amount: Math.round(order.total * 100), currency: "INR", receipt: order.id, notes: { artist_tiwari_order_id: order.id } });
    order.razorpayOrderId = rp.id;
    order.paymentStatus = "Created";
    order.updatedAt = new Date().toISOString();
    writeJson(ORDERS_FILE, orders);
    res.json({ keyId: process.env.RAZORPAY_KEY_ID, razorpayOrderId: rp.id, amount: rp.amount, currency: rp.currency, localOrderId: order.id, name: "Artist Tiwari", description: "Handmade artwork order" });
  } catch (e) { res.status(502).json({ error: e.message || "Unable to create Razorpay order." }); }
});

app.post("/api/payments/verify", requireOrderAccess, async (req, res) => {
  const { localOrderId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body || {};
  if (!localOrderId || !razorpay_order_id || !razorpay_payment_id || !razorpay_signature) return res.status(400).json({ error: "Incomplete payment verification data." });
  const orders = readJson(ORDERS_FILE);
  const order = orders.find(o => o.id === localOrderId);
  if (!order || order.razorpayOrderId !== razorpay_order_id) return res.status(400).json({ error: "Order verification failed." });
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!secret) return res.status(503).json({ error: "Razorpay secret key is not configured." });
  const expected = crypto.createHmac("sha256", secret).update(`${razorpay_order_id}|${razorpay_payment_id}`).digest("hex");
  if (!safeEqual(expected, razorpay_signature)) return res.status(400).json({ error: "Invalid payment signature." });
  if (order.paymentStatus === "Paid") return res.json({ ok: true, order, accessToken: issueOrderToken(order.id) });
  if (!deductStock(order)) return res.status(409).json({ error: "Payment received, but stock is no longer available. Contact support for a refund." });
  order.razorpayPaymentId = razorpay_payment_id;
  order.paymentStatus = "Paid";
  order.status = "Processing";
  order.updatedAt = new Date().toISOString();
  writeJson(ORDERS_FILE, orders);
  res.json({ ok: true, order, accessToken: issueOrderToken(order.id) });
});

app.post("/api/payments/webhook", (req, res) => {
  try {
    const secret = process.env.RAZORPAY_WEBHOOK_SECRET;
    if (!secret) return res.status(503).send("Webhook secret not configured");
    const signature = req.headers["x-razorpay-signature"];
    const expected = crypto.createHmac("sha256", secret).update(req.body).digest("hex");
    if (!safeEqual(expected, signature)) return res.status(400).send("Invalid signature");
    const payload = JSON.parse(req.body.toString("utf8"));
    const entity = payload?.payload?.payment?.entity;
    const rpOrderId = entity?.order_id;
    if (rpOrderId && payload.event === "payment.captured") {
      const orders = readJson(ORDERS_FILE);
      const order = orders.find(o => o.razorpayOrderId === rpOrderId);
      if (order && order.paymentStatus !== "Paid") {
        if (!deductStock(order)) return res.status(409).send("Stock unavailable");
        order.paymentStatus = "Paid";
        order.status = "Processing";
        order.razorpayPaymentId = entity.id;
        order.updatedAt = new Date().toISOString();
        writeJson(ORDERS_FILE, orders);
      }
    }
    res.json({ ok: true });
  } catch { res.status(400).send("Invalid webhook"); }
});

app.use(express.static(ROOT, { etag: false, maxAge: process.env.NODE_ENV === "production" ? "1h" : 0 }));
app.use((err, req, res, next) => { console.error("Server error:", err.message); if (res.headersSent) return next(err); res.status(500).json({ error: "Internal server error." }); });

const server = app.listen(PORT, () => console.log(`Artist Tiwari server running at http://localhost:${PORT}`));
server.on("error", error => { console.error("Unable to start server:", error.message); process.exit(1); });
