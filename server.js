// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const pool = require("./database");
const crypto = require("crypto");
const base64url = require("base64url");
const pool = require("./database"); // فرض: pool از database.js export میشه

const app = express();
app.use(cors());
app.use(bodyParser.json());

// app.post("/api/save-key", async (req, res) => {
//   const { id, public_key } = req.body;

//   if (!id || !public_key) {
//     return res.status(400).json({ error: "id و public_key الزامی هستند" });
//   }

//   try {
//     await pool.query(
//       "INSERT INTO users (id, public_key) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET public_key = $2",
//       [id, public_key]
//     );
//     res.json({ message: "✅ داده با موفقیت ذخیره شد" });
//   } catch (err) {
//     console.error("خطا در ذخیره داده:", err);
//     res.status(500).json({ error: "خطا در ذخیره داده در دیتابیس" });
//   }
// });

// app.post("/api/get-key", async (req, res) => {
//   const { id } = req.body;

//   if (!id) {
//     return res.status(400).json({ error: "id الزامی است" });
//   }

//   try {
//     const result = await pool.query(
//       "SELECT public_key FROM users WHERE id = $1",
//       [id]
//     );

//     if (result.rows.length === 0) {
//       return res.status(404).json({ error: "کاربر پیدا نشد" });
//     }

//     res.json({ id, public_key: result.rows[0].public_key });
//   } catch (err) {
//     console.error("خطا در واکشی public_key:", err);
//     res.status(500).json({ error: "خطا در دیتابیس" });
//   }
// });

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => {
//   console.log(`🚀 سرور در حال اجرا روی پورت ${PORT}`);
// });

// const crypto = require("crypto");

// // API ایجاد challenge
// app.post("/api/login-request", async (req, res) => {
//   const { id } = req.body;

//   if (!id) {
//     return res.status(400).json({ error: "id الزامی است" });
//   }

//   try {
//     // تولید رشته منحصربه‌فرد
//     const randomString = crypto.randomBytes(8).toString("hex");
//     const challenge = `${id}-${Date.now()}-${randomString}`;

//     // ذخیره در دیتابیس
//     await pool.query(
//       "INSERT INTO challenges (id, challenge, authenticated) VALUES ($1, $2, $3)",
//       [id, challenge, false]
//     );

//     // فقط id و challenge را برگردان
//     res.json({ id, challenge });
//   } catch (err) {
//     console.error("خطا در تولید challenge:", err);
//     res.status(500).json({ error: "خطا در تولید challenge" });
//   }
// });
// GET /api/auth-options?id=user@example.com
app.get("/api/auth-options", async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).json({ error: "id لازم است" });

  const user = await db.get(`SELECT * FROM users WHERE id = ?`, [id]);
  if (!user) return res.status(404).json({ error: "کاربر یافت نشد" });

  const challenge = crypto.randomBytes(32).toString("base64url");

  await db.run(
    `INSERT INTO challenges (id, challenge, authenticated) VALUES (?, ?, 0)`,
    [id, challenge]
  );

  res.json({
    publicKey: {
      challenge: challenge,
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: [
        {
          type: "public-key",
          id: user.credential_id, // اگر داری
        },
      ],
    },
  });
});
// POST /api/verify-assertion
app.post("/api/verify-assertion", async (req, res) => {
  const { id, authenticatorData, clientDataJSON, signature } = req.body;

  if (!id) return res.status(400).json({ error: "id لازم است" });

  const user = await db.get(`SELECT * FROM users WHERE id = ?`, [id]);
  if (!user) return res.status(404).json({ error: "کاربر یافت نشد" });

  // آخرین challenge ناتمام از DB بخوان
  const row = await db.get(
    `SELECT challenge FROM challenges WHERE id = ? AND authenticated = 0 ORDER BY rowid DESC LIMIT 1`,
    [id]
  );

  if (!row) return res.status(400).json({ error: "challenge پیدا نشد" });

  const publicKeyPem = user.public_key;

  // 1) decode clientDataJSON
  const clientData = JSON.parse(
    Buffer.from(clientDataJSON, "base64").toString()
  );
  if (clientData.challenge !== row.challenge)
    return res.status(400).json({ error: "challenge غلط است" });

  // 2) ساختن buffer برای verify:
  const authBuf = Buffer.from(authenticatorData, "base64");
  const clientHash = crypto
    .createHash("sha256")
    .update(Buffer.from(clientDataJSON, "base64"))
    .digest();
  const verifyBuffer = Buffer.concat([authBuf, clientHash]);

  // 3) verify RSA signature
  const isValid = crypto.verify(
    "RSA-SHA256",
    verifyBuffer,
    {
      key: publicKeyPem,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    },
    Buffer.from(signature, "base64")
  );

  if (!isValid) return res.status(400).json({ error: "امضا اشتباه است" });

  // ✅ موفقیت
  await db.run(
    `UPDATE challenges SET authenticated = 1 WHERE id = ? AND challenge = ?`,
    [id, row.challenge]
  );

  res.json({ success: true });
});
// POST /api/register-challenge
app.post("/api/register-challenge", async (req, res) => {
  const { id } = req.body;

  if (!id) return res.status(400).json({ error: "id لازم است" });

  // تولید challenge
  const challenge = crypto.randomBytes(32).toString("base64url");

  // در دیتابیس ذخیره کن تا بعداً برای verify استفاده شود (اختیاری)
  await pool.query(
    "INSERT INTO challenges (id, challenge, authenticated) VALUES ($1, $2, $3)",
    [id, challenge, false]
  );

  // بازگشت ساختار مورد نیاز برای WebAuthn registration
  res.json({
    publicKey: {
      challenge,
      rp: {
        name: "Passkey Demo",
        id: "passkey-backend-xht7.onrender.com", // باید با دامنه backend یکی باشد
      },
      user: {
        id: Buffer.from(id).toString("base64url"), // در WebAuthn باید ArrayBuffer باشد
        name: id,
        displayName: id,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -257 }, // RSA256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform", // ذخیره در secure element
        userVerification: "preferred",
      },
      timeout: 60000,
      attestation: "direct", // یا "none"
    },
  });
});
