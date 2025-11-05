// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const pool = require("./database");

const app = express();
app.use(cors());
app.use(bodyParser.json());

app.post("/api/save-key", async (req, res) => {
  const { id, public_key } = req.body;

  if (!id || !public_key) {
    return res.status(400).json({ error: "id و public_key الزامی هستند" });
  }

  try {
    await pool.query(
      "INSERT INTO users (id, public_key) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET public_key = $2",
      [id, public_key]
    );
    res.json({ message: "✅ داده با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("خطا در ذخیره داده:", err);
    res.status(500).json({ error: "خطا در ذخیره داده در دیتابیس" });
  }
});

app.post("/api/get-key", async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ error: "id الزامی است" });
  }

  try {
    const result = await pool.query(
      "SELECT public_key FROM users WHERE id = $1",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "کاربر پیدا نشد" });
    }

    res.json({ id, public_key: result.rows[0].public_key });
  } catch (err) {
    console.error("خطا در واکشی public_key:", err);
    res.status(500).json({ error: "خطا در دیتابیس" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 سرور در حال اجرا روی پورت ${PORT}`);
});

const crypto = require("crypto");

// API ایجاد challenge
app.post("/api/login-request", async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(400).json({ error: "id الزامی است" });
  }

  try {
    // تولید رشته منحصربه‌فرد
    const randomString = crypto.randomBytes(8).toString("hex");
    const challenge = `${id}-${Date.now()}-${randomString}`;

    // ذخیره در دیتابیس
    await pool.query(
      "INSERT INTO challenges (id, challenge, authenticated) VALUES ($1, $2, $3)",
      [id, challenge, false]
    );

    // فقط id و challenge را برگردان
    res.json({ id, challenge });
  } catch (err) {
    console.error("خطا در تولید challenge:", err);
    res.status(500).json({ error: "خطا در تولید challenge" });
  }
});
