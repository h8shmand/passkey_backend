// server.js
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const base64url = require("base64url");
const pool = require("./database"); // انتظار: Pool از pg (Postgres)

const app = express();
app.use(cors());
app.use(express.json()); // body parser

// -----------------------------
// POST /api/save-key
// ذخیره public_key برای id
// -----------------------------
app.post("/api/save-key", async (req, res) => {
  const { id, public_key } = req.body;

  if (!id || !public_key) {
    return res.status(400).json({ error: "id و public_key الزامی هستند" });
  }

  try {
    await pool.query(
      `INSERT INTO users (id, public_key)
       VALUES ($1, $2)
       ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key`,
      [id, public_key]
    );
    res.json({ message: "✅ داده با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("خطا در ذخیره داده:", err);
    res.status(500).json({ error: "خطا در ذخیره داده در دیتابیس" });
  }
});

// -----------------------------
// POST /api/get-key
// برگرداندن public_key براساس id
// -----------------------------
app.post("/api/get-key", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id الزامی است" });

  try {
    const result = await pool.query(
      `SELECT public_key FROM users WHERE id = $1`,
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

// -----------------------------
// POST /api/login-request
// تولید یک challenge مبتنی بر id (برای جریان ساده‌تر)
// -----------------------------
app.post("/api/login-request", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id الزامی است" });

  try {
    const randomString = crypto.randomBytes(8).toString("hex");
    const challenge = `${id}-${Date.now()}-${randomString}`;

    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated)
       VALUES ($1, $2, $3)`,
      [id, challenge, false]
    );

    res.json({ id, challenge });
  } catch (err) {
    console.error("خطا در تولید challenge:", err);
    res.status(500).json({ error: "خطا در تولید challenge" });
  }
});

// -----------------------------
// GET /api/auth-options?id=...
// برگرداندن publicKey گزینه‌ها برای navigator.credentials.get()
// -----------------------------
app.get("/api/auth-options", async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).json({ error: "id لازم است" });

  try {
    const userRes = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    if (userRes.rows.length === 0)
      return res.status(404).json({ error: "کاربر یافت نشد" });

    const user = userRes.rows[0];

    // تولید challenge باینری به صورت base64url
    const challengeBuf = crypto.randomBytes(32);
    const challenge = base64url.encode(challengeBuf);

    // ذخیره در challenges برای verify بعدی
    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated, created_at)
       VALUES ($1, $2, $3, NOW())`,
      [id, challenge, false]
    );

    // اگر credential_id در users ذخیره شده باشد، آن را در allowCredentials قرار بده
    // فرض می‌کنیم ستون credential_id (bytea/text base64url) ممکن است وجود داشته باشد
    const allowCredentials = [];
    if (user.credential_id) {
      allowCredentials.push({
        type: "public-key",
        id: user.credential_id, // client-side باید این id را به ArrayBuffer تبدیل کند
      });
    }

    res.json({
      publicKey: {
        challenge: challenge,
        timeout: 60000,
        userVerification: "preferred",
        allowCredentials,
      },
    });
  } catch (err) {
    console.error("خطا در auth-options:", err);
    res.status(500).json({ error: "خطا در تولید auth options" });
  }
});

// -----------------------------
// POST /api/verify-assertion
// بررسی assertion دریافتی از client
// ورودی: { id, authenticatorData (base64url), clientDataJSON (base64url), signature (base64url) }
// -----------------------------
app.post("/api/verify-assertion", async (req, res) => {
  const { id, authenticatorData, clientDataJSON, signature } = req.body;
  if (!id || !authenticatorData || !clientDataJSON || !signature) {
    return res.status(400).json({ error: "پارامترهای لازم فرستاده نشده‌اند" });
  }

  try {
    // 1) گرفتن user و public_key
    const userRes = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    if (userRes.rows.length === 0)
      return res.status(404).json({ error: "کاربر وجود ندارد" });
    const user = userRes.rows[0];
    const publicKeyPem = user.public_key;
    if (!publicKeyPem)
      return res
        .status(500)
        .json({ error: "public_key برای کاربر موجود نیست" });

    // 2) خواندن آخرین challenge pending
    const chalRes = await pool.query(
      `SELECT challenge FROM challenges WHERE id = $1 AND authenticated = false ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    if (chalRes.rows.length === 0)
      return res.status(400).json({
        error: "هیچ challenge در حالت pending برای این کاربر وجود ندارد",
      });
    const storedChallenge = chalRes.rows[0].challenge;

    // 3) decode clientDataJSON و مقایسه challenge
    const clientDataBuf = Buffer.from(clientDataJSON, "base64");
    let clientData;
    try {
      clientData = JSON.parse(clientDataBuf.toString("utf8"));
    } catch (e) {
      return res.status(400).json({ error: "clientDataJSON قابل parse نیست" });
    }

    // clientData.challenge معمولاً base64url-encoded است. تلاش برای decode و مقایسه:
    let clientChallenge = clientData.challenge;
    try {
      // اگر قابل base64url-decoding باشد آن را decode کن
      const decoded = base64url.decode(clientChallenge);
      // decoded ممکن است بایت‌ها یا رشته‌ی اصلی challenge باشد؛ تبدیل به رشته برای مقایسه
      clientChallenge = decoded;
    } catch (e) {
      // اگر decode نشد، از همان مقدار متنی استفاده کن
    }

    if (
      clientChallenge !== storedChallenge &&
      clientData.challenge !== storedChallenge
    ) {
      return res.status(400).json({ error: "challenge تطابق ندارد" });
    }

    // 4) آماده‌سازی داده برای verify: authenticatorData (raw) || SHA256(clientDataJSON)
    const authBuf = Buffer.from(authenticatorData, "base64");
    const clientHash = crypto
      .createHash("sha256")
      .update(clientDataBuf)
      .digest();
    const verificationData = Buffer.concat([authBuf, clientHash]);

    // signature از client معمولاً به صورت base64 (نرمال) یا base64url ارسال می‌شود. تلاش برای decode:
    let signatureBuf;
    try {
      signatureBuf = Buffer.from(signature, "base64");
    } catch (e) {
      // fallback: try base64url
      signatureBuf = Buffer.from(base64url.toBuffer(signature));
    }

    // 5) verify با public key PEM
    const verified = crypto.verify(
      "sha256",
      verificationData,
      {
        key: publicKeyPem,
      },
      signatureBuf
    );

    if (!verified) {
      return res.status(400).json({ error: "امضای دریافتی معتبر نیست" });
    }

    // 6) علامتگذاری authenticated
    await pool.query(
      `UPDATE challenges SET authenticated = true WHERE id = $1 AND challenge = $2`,
      [id, storedChallenge]
    );

    return res.json({ success: true, message: "اعتبارسنجی موفق بود" });
  } catch (err) {
    console.error("خطا در verify-assertion:", err);
    return res.status(500).json({ error: "خطای سرور در بررسی assertion" });
  }
});

// -----------------------------
// POST /api/register-challenge
// تولید challenge برای registration (اگر client خواست از سرور بگیرد)
// -----------------------------
app.post("/api/register-challenge", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id لازم است" });

  try {
    const challenge = base64url.encode(crypto.randomBytes(32));

    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated, created_at) VALUES ($1, $2, $3, NOW())`,
      [id, challenge, false]
    );

    res.json({
      publicKey: {
        challenge,
        rp: {
          name: "Passkey Demo",
          id: "passkey-v2.netlify.app",
        },
        user: {
          id: base64url.encode(Buffer.from(id)),
          name: id,
          displayName: id,
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "preferred",
        },
        timeout: 60000,
        attestation: "direct",
      },
    });
  } catch (err) {
    console.error("خطا در register-challenge:", err);
    res.status(500).json({ error: "خطا در تولید register challenge" });
  }
});

// -----------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 سرور در حال اجرا روی پورت ${PORT}`);
});
