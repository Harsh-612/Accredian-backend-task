const express = require("express");
const mysql = require("mysql"); // I am capable of using Prisma or Drizzle to operate mySQL as well!!
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const cors = require("cors");
const dotenv = require("dotenv");
const { v4: uuidv4 } = require("uuid");
const newUUID = uuidv4();
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(bodyParser.json());

app.use(cors());
// Connection
const db = mysql.createConnection({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.DB_PASSWD,
  database: process.env.NAME_DB,
});

// Connect
db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL:", err);
  } else {
    console.log("Connected to MySQL");
  }
});

// Endpoint - registration
app.post("/api/register", async (req, res) => {
  try {
    const { email, username, password } = req.body;

    // Check for duplicate email or username
    const checkDuplicateQuery =
      "SELECT * FROM users WHERE email = ? OR username = ?";
    const duplicateCheckResults = await db.query(checkDuplicateQuery, [
      email,
      username,
    ]);

    if (duplicateCheckResults.length > 0) {
      // Duplicate found
      return res
        .status(400)
        .json({ error: "Email or username already exists" });
    }

    // Hashing
    const hashedPassword = await bcrypt.hash(password, 12);

    // Inserting the user
    const insertQuery =
      "INSERT INTO users (id,email, username, password) VALUES (?, ?, ?)";
    await db.query(insertQuery, [newUUID, email, username, hashedPassword]);

    res.status(201).json({ message: "Registration successful" });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Endpoint - login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const query = "SELECT * FROM users WHERE username = ?";
    const results = await db.query(query, [username]);

    if (results.length === 0) {
      // User not found
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = results[0];

    // Verifying passwords
    const success = await bcrypt.compare(password, user.password);

    if (success) {
      // Sucessful login - password match
      res.status(200).json({ message: "Login successful" });
    } else {
      // Passwords don't match
      res.status(401).json({ error: "Invalid credentials" });
    }
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ error: "Internal Error" });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
