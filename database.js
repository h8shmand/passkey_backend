// database.js
const { Pool } = require("pg");

// از متغیر محیطی DATABASE_URL استفاده می‌کنیم
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // برای Render لازم است
});

// ایجاد جدول (اگر وجود ندارد)
(async () => {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL
      );
    `);
    console.log("✅ جدول users آماده است");
  } catch (err) {
    console.error("❌ خطا در ایجاد جدول:", err);
  } finally {
    client.release();
  }
})();

(async () => {
  const client = await pool.connect();
  try {
    // جدول users (قبلاً ساخته شده)
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL
      );
    `);

    // جدول challenges جدید
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
