const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ایجاد جدول (اگر وجود ندارد)
(async () => {
  const client = await pool.connect();
  try {
    // جدول users با ستون credential_id
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        credential_id TEXT,   -- اضافه شد
        alg INT              -- اضافه شد (اختیاری برای نگهداری alg)
      );
    `);

    // جدول challenges
    await client.query(`
      CREATE TABLE IF NOT EXISTS challenges (
        id TEXT NOT NULL,
        challenge TEXT NOT NULL,
        authenticated BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    console.log("✅ جداول آماده هستند");
  } catch (err) {
    console.error("❌ خطا در ایجاد جدول:", err);
  } finally {
    client.release();
  }
})();

module.exports = pool;
