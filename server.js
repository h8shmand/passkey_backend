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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 سرور در حال اجرا روی پورت ${PORT}`);
});
