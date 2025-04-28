require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors({
    origin: "http://localhost:5173",  // Adjust based on your frontend
    methods: ["GET", "POST"],
    credentials: true
}));
app.use(express.urlencoded({ extended: true }));

// ✅ Connect to MySQL Database
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect((err) => {
    if (err) {
        console.error("❌ Database connection failed:", err);
    } else {
        console.log("✅ Connected to MySQL database!");
    }
});

// ✅ Ensure users table exists
db.query(
    `CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(100) PRIMARY KEY,
        fullname VARCHAR(100) NOT NULL,
        password VARCHAR(255) NOT NULL
    )`,
    (err) => {
        if (err) console.error("Error creating users table:", err);
    }
);

// ✅ Ensure scores table exists
db.query(
    `CREATE TABLE IF NOT EXISTS scores (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(100) NOT NULL,
        concept_id INT NOT NULL,
        level1_score INT DEFAULT 0,
        level2_score INT DEFAULT 0,
        level3_score INT DEFAULT 0,
        UNIQUE (email, concept_id),
        FOREIGN KEY (email) REFERENCES users(email) ON DELETE CASCADE
    )`,
    (err) => {
        if (err) console.error("Error creating scores table:", err);
    }
);

// ✅ Serve static files (HTML, CSS, JS)
app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "start.html"));
});

app.get("/option", (req, res) => {
    res.sendFile(path.join(__dirname, "option.html"));
});

app.get("/register-page", (req, res) => {
    res.sendFile(path.join(__dirname, "register.html"));
});

// ==================  🟢 USER REGISTRATION ROUTE  ================== //
app.post("/register", (req, res) => {
    const { fullname, email, password, retypePassword } = req.body;

    if (!fullname || !email || !password || !retypePassword) {
        return res.json({ success: false, message: "All fields are required!" });
    }

    if (password !== retypePassword) {
        return res.json({ success: false, message: "Passwords do not match!" });
    }

    const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkEmailQuery, [email], (err, result) => {
        if (err) return res.json({ success: false, message: "Server error!" });
        if (result.length > 0) return res.json({ success: false, message: "Email already registered!" });

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) return res.json({ success: false, message: "Error hashing password!" });

            const insertUserQuery = "INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)";
            db.query(insertUserQuery, [fullname, email, hash], (err) => {
                if (err) return res.json({ success: false, message: "Database error!" });
                return res.json({ success: true, message: "Registration successful!" });
            });
        });
    });
});

// ==================  🔵 USER LOGIN ROUTE  ================== //
app.post("/login", (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: "All fields are required!" });
    }

    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], (err, results) => {
        if (err) return res.json({ success: false, message: "Database error" });
        if (results.length === 0) return res.json({ success: false, message: "User not found!" });

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.json({ success: false, message: "Error comparing passwords!" });
            if (!isMatch) return res.json({ success: false, message: "Incorrect password!" });

            return res.json({ 
                success: true, 
                message: "Login successful!", 
                username: user.fullname,
                email: user.email 
            });
        });
    });
});

// ==================  🔴 RESET PASSWORD ROUTE  ================== //
app.post("/reset-password", (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: "Email and new password are required!" });
    }

    // Check if email exists
    const checkEmailQuery = "SELECT * FROM users WHERE email = ?";
    db.query(checkEmailQuery, [email], async (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Database error!" });

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: "User not found!" });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password in database
        const updatePasswordQuery = "UPDATE users SET password = ? WHERE email = ?";
        db.query(updatePasswordQuery, [hashedPassword, email], (err, updateResult) => {
            if (err) return res.status(500).json({ success: false, message: "Error updating password!" });

            res.json({ success: true, message: "Password reset successfully!" });
        });
    });
});

// ==================  🟠 SUBMIT FEEDBACK ROUTE  ================== //
app.post("/submit-feedback", (req, res) => {
    const { rating, feedback } = req.body;

    if (!rating || !feedback.trim()) {
        return res.status(400).json({ success: false, message: "Rating and feedback are required!" });
    }

    const sql = "INSERT INTO feedbacks (rating, feedback) VALUES (?, ?)";
    db.query(sql, [rating, feedback], (err) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Database error" });
        }
        res.json({ success: true, message: "Feedback saved successfully!" });
    });
});

// ==================  🟠 SUBMIT SCORE ROUTE  ================== //
app.post("/submit-score", (req, res) => {
    const { email, concept_id, level1_score, level2_score, level3_score } = req.body;

    console.log("📩 Received request:", req.body);

    if (!email || !concept_id) {
        console.error("❌ Missing required fields!");
        return res.status(400).json({ message: "Email and concept ID are required!" });
    }

    const checkQuery = "SELECT * FROM scores WHERE email = ? AND concept_id = ?";
    db.query(checkQuery, [email, concept_id], (err, rows) => {
        if (err) {
            console.error("❌ Database error:", err);
            return res.status(500).json({ message: "Database error" });
        }

        if (rows.length === 0) {
            // Insert new record
            const insertQuery = `INSERT INTO scores (email, concept_id, level1_score, level2_score, level3_score) 
                                 VALUES (?, ?, ?, ?, ?)`;
            db.query(insertQuery, [email, concept_id, level1_score || 0, level2_score || 0, level3_score || 0], (insertErr) => {
                if (insertErr) {
                    console.error("❌ Error inserting score:", insertErr);
                    return res.status(500).json({ message: "Database error" });
                }
                console.log("✅ Score inserted successfully!");
                return res.json({ success: true, message: "Score saved successfully!" });
            });

        } else {
            // Update existing record
            const updateQuery = `UPDATE scores SET 
                level1_score = IFNULL(?, level1_score), 
                level2_score = IFNULL(?, level2_score), 
                level3_score = IFNULL(?, level3_score) 
                WHERE email = ? AND concept_id = ?`;
            db.query(updateQuery, [level1_score, level2_score, level3_score, email, concept_id], (updateErr) => {
                if (updateErr) {
                    console.error("❌ Error updating score:", updateErr);
                    return res.status(500).json({ message: "Database error" });
                }
                console.log("✅ Score updated successfully!");
                return res.json({ success: true, message: "Score updated successfully!" });
            });
        }
    });
});
// ==================  🟡 concept file score  ================== //

app.get("/getTotalLevel3Score", (req, res) => {
    const email = req.query.email; // Get email from query params

    const sql = `SELECT SUM(level3_score) AS totalLevel3Score FROM scores WHERE email = ?`;

    db.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        console.log(result);  // Debugging line
        res.json({ totalLevel3Score: result[0].totalLevel3Score || 0 });
    });
});

// ==================  🟡 START SERVER  ================== //
const PORT = 3000;
app.listen(PORT, () => {
    console.log("🚀 Server is running at http://localhost:" + PORT);
});