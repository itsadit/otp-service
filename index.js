const express = require('express');
const mysql = require('mysql2/promise');
require('dotenv').config();
const cors = require('cors');
const app = express();
app.use(express.json());
app.use(cors());

// database connection
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// helper function
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

/**
 * Calculates the remaining cooldown time for a rolling window limit.
 */
const getRemainingCooldown = (earliestRequestTime) => {
    const now = new Date();
    const cooldownPeriodMs = 15 * 60 * 1000; // 15 minutes in milliseconds
    const earliestRequestMs = earliestRequestTime.getTime();
    const elapsedTimeMs = now.getTime() - earliestRequestMs;
    // Ensure the result is not negative
    return Math.max(0, Math.ceil((cooldownPeriodMs - elapsedTimeMs) / 1000));
};

// --- Endpoints ---

app.get('/', (req, res) => {
    res.status(200).send('OTP service is running. Use POST to /otp/request or /otp/verify.');
});

/**
 * POST /otp/request
 * Handles the generation of a new OTP, performing idempotency and rate limit checks first.
 */
app.post('/otp/request', async (req, res) => {
    const { user_id, purpose } = req.body;
    const ip_address = req.ip;
    const idempotencyKey = req.get('Idempotency-Key');

    if (!user_id || !purpose || !idempotencyKey) {
        return res.status(400).json({ reason: 'user_id, purpose, and Idempotency-Key are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();

        // Step 1: Idempotency check
        const [idempotencyResult] = await connection.execute(
            `SELECT response_status_code, response_body, created_at FROM idempotency WHERE idempotency_key = ?`,
            [idempotencyKey]
        );

        if (idempotencyResult.length > 0) {
            const entry = idempotencyResult[0];
            const now = new Date();
            const created_at = new Date(entry.created_at);
            const tenMinutesInMs = 10 * 60 * 1000;

            if (now.getTime() - created_at.getTime() < tenMinutesInMs) {
                // Return cached response
                return res.status(entry.response_status_code).json(JSON.parse(entry.response_body));
            }
        }

        // --- FIX: Start transaction for atomic rate limit and OTP generation ---
        await connection.beginTransaction();

        // Step 2: Rolling window rate limit checks
        const [userRequests] = await connection.execute(
            `SELECT created_at FROM rate_limits WHERE user_id = ? AND created_at >= NOW() - INTERVAL '15' MINUTE ORDER BY created_at ASC FOR UPDATE`,
            [user_id]
        );
        const [ipRequests] = await connection.execute(
            `SELECT created_at FROM rate_limits WHERE ip_address = ? AND created_at >= NOW() - INTERVAL '15' MINUTE ORDER BY created_at ASC FOR UPDATE`,
            [ip_address]
        );

        if (userRequests.length >= 3) {
            await connection.rollback();
            const cooldown = getRemainingCooldown(userRequests[0].created_at);
            const response = { reason: 'user_rate_limit_exceeded', cooldown_seconds_remaining: cooldown };
            await connection.execute(`INSERT INTO idempotency (idempotency_key, response_status_code, response_body) VALUES (?, ?, ?)`,
                [idempotencyKey, 429, JSON.stringify(response)]
            );
            return res.status(429).json(response);
        }

        if (ipRequests.length >= 8) {
            await connection.rollback();
            const cooldown = getRemainingCooldown(ipRequests[0].created_at);
            const response = { reason: 'ip_rate_limit_exceeded', cooldown_seconds_remaining: cooldown };
            await connection.execute(`INSERT INTO idempotency (idempotency_key, response_status_code, response_body) VALUES (?, ?, ?)`,
                [idempotencyKey, 429, JSON.stringify(response)]
            );
            return res.status(429).json(response);
        }

        // Step 3: Check for an active OTP with a lock to enforce single-active-OTP rule.
        const [activeOtp] = await connection.execute(
            `SELECT id FROM otps WHERE user_id = ? AND purpose = ? AND status = 'active' FOR UPDATE`,
            [user_id, purpose]
        );

        if (activeOtp.length > 0) {
            await connection.rollback();
            const response = { reason: 'An active OTP already exists.' };
            await connection.execute(`INSERT INTO idempotency (idempotency_key, response_status_code, response_body) VALUES (?, ?, ?)`,
                [idempotencyKey, 409, JSON.stringify(response)]
            );
            return res.status(409).json(response);
        }

        const otpCode = generateOTP();
        const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

        // Insert the new OTP
        const [insertResult] = await connection.execute(
            `INSERT INTO otps (user_id, purpose, otp_code, expires_at) VALUES (?, ?, ?, ?)`,
            [user_id, purpose, otpCode, expiresAt]
        );
        const otpId = insertResult.insertId;

        // Log the new request for rate limiting
        await connection.execute(
            `INSERT INTO rate_limits (user_id, ip_address) VALUES (?, ?)`,
            [user_id, ip_address]
        );

        await connection.commit();

        const responseBody = {
            otp_id: otpId,
            ttl: 300,
            remaining_user_requests: 2 - userRequests.length,
            remaining_ip_requests: 7 - ipRequests.length
        };

        // Cache the successful response for idempotency
        await connection.execute(`INSERT INTO idempotency (idempotency_key, response_status_code, response_body) VALUES (?, ?, ?)`,
            [idempotencyKey, 201, JSON.stringify(responseBody)]
        );

        res.status(201).json(responseBody);
    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error('Request handler error:', error);
        res.status(500).json({ reason: 'Internal Server Error' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

/**
 * POST /otp/verify
 * Handles OTP verification, including checks for correctness, attempts, and expiration.
 */
app.post('/otp/verify', async (req, res) => {
    const { user_id, purpose, otp_code } = req.body;

    if (!user_id || !purpose || !otp_code) {
        return res.status(400).json({ reason: 'user_id, purpose, and otp_code are required.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();

        // Find and lock the OTP to ensure exactly-once success under concurrency
        const [otpRows] = await connection.execute(
            `SELECT id, otp_code, status, attempts, expires_at FROM otps WHERE user_id = ? AND purpose = ? FOR UPDATE`,
            [user_id, purpose]
        );

        if (otpRows.length === 0) {
            await connection.rollback();
            return res.status(410).json({ reason: 'code_expired' });
        }

        const otp = otpRows[0];
        const now = new Date();

        // Check 1: Ensure the OTP is in an 'active' state before doing anything else.
        if (otp.status !== 'active') {
            await connection.rollback();
            return res.status(410).json({ reason: 'code_used' });
        }

        // Check 2: Now that we know it's active, check for expiration.
        if (otp.expires_at.getTime() < now.getTime()) {
            await connection.execute(`UPDATE otps SET status = 'expired' WHERE id = ?`, [otp.id]);
            await connection.commit();
            return res.status(410).json({ reason: 'code_expired' });
        }

        // Check 3: Check for code correctness and max attempts.
        if (otp.otp_code !== otp_code) {
            const newAttempts = otp.attempts + 1;
            if (newAttempts >= 3) {
                // Lock the OTP after 3 wrong attempts
                await connection.execute(`UPDATE otps SET attempts = ?, status = 'locked' WHERE id = ?`, [newAttempts, otp.id]);
                await connection.commit();
                return res.status(401).json({ reason: 'attempts_exceeded' });
            } else {
                // Increment attempts and return remaining count
                await connection.execute(`UPDATE otps SET attempts = ? WHERE id = ?`, [newAttempts, otp.id]);
                await connection.commit();
                return res.status(401).json({ reason: 'wrong_code', attempts_remaining: 3 - newAttempts });
            }
        }

        // If all checks pass, mark OTP as used to ensure exactly-once success
        const [updateResult] = await connection.execute(`
            UPDATE otps SET status = 'used' WHERE id = ? AND status = 'active'
        `, [otp.id]);

        if (updateResult.affectedRows === 0) {
            await connection.rollback();
            return res.status(410).json({ reason: 'OTP already used' });
        }

        await connection.commit();

        res.status(200).json({ message: 'OTP verified successfully.' });

    } catch (error) {
        if (connection) {
            await connection.rollback();
        }
        console.error('Verify handler error:', error);
        res.status(500).json({ reason: 'Internal Server Error' });
    } finally {
        if (connection) {
            connection.release();
        }
    }
});

app.listen(process.env.PORT, () => {
    console.log(`Server is running on port ${process.env.PORT}`);
});
