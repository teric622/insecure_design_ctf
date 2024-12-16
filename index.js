const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const app = express();

// Constants
const FLAG = "CTF{Authorization_Bypass_Success}";
const SESSION_EXPIRATION = 3 * 60 * 1000; // 2 minutes
const users = {
  user: { password: "userpass", role: "user" },
  admin: { password: "adminpass", role: "admin" },
};

// In-Memory Store for Session Timestamps
const sessionStore = new Map();

// Utility Functions
function encodeHex(str) {
  return Buffer.from(str, "utf8").toString("hex");
}

function decodeHex(hex) {
  return Buffer.from(hex, "hex").toString("utf8");
}

function generateFakeHash() {
  // Generate a fake MD5 hash (static for this example)
  return crypto.createHash("md5").update("hello").digest("hex"); // Outputs: 5d41402abc4b2a76b9719d911017c592
}

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use((req, res, next) => {
  if (req.path.includes("admin") || req.path.includes("flag")) {
    console.log(`Unauthorized attempt to access ${req.path}`);
  }
  next();
});

// Routes
app.get("/", (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <label>Username:</label><input type="text" name="username" required />
      <label>Password:</label><input type="password" name="password" required />
      <button type="submit">Login</button>
    </form>
    <!-- Ensure your session token is correct to view all features -->
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (user && user.password === password) {
    const fakeHash = generateFakeHash();
    const sessionData = `${username}$${user.role}$${Date.now()}`;
    const sessionToken = encodeHex(`${fakeHash}|${sessionData}`);
    sessionStore.set(sessionToken, Date.now());
    res.cookie("session", sessionToken);
    res.redirect("/dashboard");
  } else {
    res.status(403).send("Invalid credentials.");
  }
});

app.get("/dashboard", (req, res) => {
  const session = req.cookies.session;
  if (!session) return res.status(403).send("Not logged in.");

  const decoded = decodeHex(session);
  const [fakeHash, sessionData] = decoded.split("|"); // Split the fake hash and session data
  const [username, role, timestamp] = sessionData.split("$"); // Split session data fields
  const currentTime = Date.now();

  if (currentTime - parseInt(timestamp, 10) > SESSION_EXPIRATION) {
    return res.status(403).send("Session expired. Please log in again.");
  }

  if (role === "admin") {
    res.send(`<h1>Admin Dashboard</h1><p>Flag: ${FLAG}</p>`);
  } else if (role === "user") {
    res.send(`<h1>User Dashboard</h1><p>Welcome, ${username}!</p>`);
  } else {
    res.status(403).send("Invalid session.");
  }
});

app.get("/admin-panel", (req, res) => {
  res.status(403).send("Restricted access. Admins only.");
});

app.get("/get-flag", (req, res) => {
  res.status(403).send("Unauthorized request.");
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});