// server.js
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const base64url = require("base64url");
const pool = require("./database"); // Pool از pg

const app = express();
app.use(cors());
app.use(express.json());

// POST /api/save-key
app.post("/api/save-key", async (req, res) => {
  const { id, public_key, credential_id } = req.body;
  if (!id || !public_key) return res.status(400).json({ error: "id و public_key الزامی هستند" });

  try {
    // اگر credential_id ارسال شد آن را هم ذخیره کن (اختیاری، برای allowCredentials)
    if (credential_id) {
      await pool.query(
        `INSERT INTO users (id, public_key, credential_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key, credential_id = EXCLUDED.credential_id`,
        [id, public_key, credential_id]
      );
    } else {
      await pool.query(
        `INSERT INTO users (id, public_key)
         VALUES ($1, $2)
         ON CONFLICT (id) DO UPDATE SET public_key = EXCLUDED.public_key`,
        [id, public_key]
      );
    }
    res.json({ message: "✅ داده با موفقیت ذخیره شد" });
  } catch (err) {
    console.error("خطا در ذخیره داده:", err);
    res.status(500).json({ error: "خطا در ذخیره داده در دیتابیس" });
  }
});

// POST /api/get-key
app.post("/api/get-key", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id الزامی است" });

  try {
    const result = await pool.query(`SELECT public_key FROM users WHERE id = $1`, [id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "کاربر پیدا نشد" });
    res.json({ id, public_key: result.rows[0].public_key });
  } catch (err) {
    console.error("خطا در واکشی public_key:", err);
    res.status(500).json({ error: "خطا در دیتابیس" });
  }
});

// POST /api/login-request (ساده)
app.post("/api/login-request", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id الزامی است" });

  try {
    const randomString = crypto.randomBytes(8).toString("hex");
    const challenge = `${id}-${Date.now()}-${randomString}`;

    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated) VALUES ($1, $2, $3)`,
      [id, challenge, false]
    );

    res.json({ id, challenge });
  } catch (err) {
    console.error("خطا در تولید challenge:", err);
    res.status(500).json({ error: "خطا در تولید challenge" });
  }
});

// GET /api/auth-options?id=...
app.get("/api/auth-options", async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).json({ error: "id لازم است" });

  try {
    const userRes = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "کاربر یافت نشد" });
    const user = userRes.rows[0];

    const challengeBuf = crypto.randomBytes(32);
    const challenge = base64url.encode(challengeBuf);

    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated, created_at) VALUES ($1, $2, $3, NOW())`,
      [id, challenge, false]
    );

    const allowCredentials = [];
    if (user.credential_id) {
      allowCredentials.push({
        type: "public-key",
        id: user.credential_id,
      });
    }

    res.json({
      publicKey: {
        challenge,
        timeout: 60000,
        userVerification: "preferred",
        allowCredentials,
        // pubKeyCredParams not required for get(); rely on stored credential
      },
    });
  } catch (err) {
    console.error("خطا در auth-options:", err);
    res.status(500).json({ error: "خطا در تولید auth options" });
  }
});

// POST /api/verify-assertion
app.post("/api/verify-assertion", async (req, res) => {
  const { id, authenticatorData, clientDataJSON, signature } = req.body;
  if (!id || !authenticatorData || !clientDataJSON || !signature) {
    return res.status(400).json({ error: "پارامترهای لازم فرستاده نشده‌اند" });
  }

  try {
    const userRes = await pool.query(`SELECT * FROM users WHERE id = $1`, [id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "کاربر وجود ندارد" });
    const user = userRes.rows[0];
    const publicKeyPem = user.public_key;
    if (!publicKeyPem) return res.status(500).json({ error: "public_key برای کاربر موجود نیست" });

    const chalRes = await pool.query(
      `SELECT challenge FROM challenges WHERE id = $1 AND authenticated = false ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    if (chalRes.rows.length === 0) return res.status(400).json({ error: "هیچ challenge pending برای این کاربر یافت نشد" });
    const storedChallenge = chalRes.rows[0].challenge;

    // decode clientDataJSON (base64 or base64url)
    let clientDataBuf;
    try {
      clientDataBuf = Buffer.from(clientDataJSON, "base64");
    } catch (e) {
      clientDataBuf = Buffer.from(base64url.toBuffer(clientDataJSON));
    }

    let clientData;
    try {
      clientData = JSON.parse(clientDataBuf.toString("utf8"));
    } catch (e) {
      return res.status(400).json({ error: "clientDataJSON قابل parse نیست" });
    }

    // clientData.challenge ممکن است base64url encoded باشد
    let clientChallenge = clientData.challenge;
    try {
      const decoded = base64url.decode(clientChallenge);
      clientChallenge = decoded;
    } catch (e) { /* keep as is */ }

    if (clientChallenge !== storedChallenge && clientData.challenge !== storedChallenge) {
      return res.status(400).json({ error: "challenge تطابق ندارد" });
    }

    // verificationData = authenticatorData (raw) || SHA256(clientDataJSON)
    const authBuf = Buffer.from(authenticatorData, "base64");
    const clientHash = crypto.createHash("sha256").update(clientDataBuf).digest();
    const verificationData = Buffer.concat([authBuf, clientHash]);

    // decode signature (base64 or base64url)
    let signatureBuf;
    try {
      signatureBuf = Buffer.from(signature, "base64");
    } catch (e) {
      signatureBuf = Buffer.from(base64url.toBuffer(signature));
    }

    // Try ECDSA (ES256) first
    let verified = false;
    try {
      verified = crypto.verify("sha256", verificationData, publicKeyPem, signatureBuf);
    } catch (e) {
      verified = false;
    }

    // If not ECDSA, try RSA PKCS1 v1.5 (alg -257)
    if (!verified) {
      try {
        verified = crypto.verify(
          "sha256",
          verificationData,
          {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PADDING,
          },
          signatureBuf
        );
      } catch (e) {
        verified = false;
      }
    }

    if (!verified) return res.status(400).json({ error: "امضای دریافتی معتبر نیست" });

    // mark challenge authenticated
    await pool.query(`UPDATE challenges SET authenticated = true WHERE id = $1 AND challenge = $2`, [id, storedChallenge]);

    return res.json({ success: true, message: "اعتبارسنجی موفق بود" });
  } catch (err) {
    console.error("خطا در verify-assertion:", err);
    return res.status(500).json({ error: "خطای سرور در بررسی assertion" });
  }
});

// POST /api/register-challenge
app.post("/api/register-challenge", async (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: "id لازم است" });

  try {
    const challenge = base64url.encode(crypto.randomBytes(32));

    await pool.query(
      `INSERT INTO challenges (id, challenge, authenticated, created_at) VALUES ($1, $2, $3, NOW())`,
      [id, challenge, false]
    );

    // تعیین rp.id بر اساس origin درخواست‌دهنده (اگر موجود باشد)
    let originHost = null;
    try {
      originHost = req.headers.origin ? new URL(req.headers.origin).hostname : null;
    } catch (e) {
      originHost = null;
    }

    // fallback: اگر origin ناآشناست، از hostname سرور استفاده کن (در deploy باید دقت شود)
    const rpId = originHost || "passkey-backend-xht7.onrender.com";

    res.json({
      publicKey: {
        challenge,
        rp: {
          name: "Passkey Demo",
          id: rpId,
        },
        user: {
          id: base64url.encode(Buffer.from(id)),
          name: id,
          displayName: id,
        },
        // اینجا هر دو الگوریتم را می‌فرستیم: اول ES256 بعد RSA
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },    // ES256
          { type: "public-key", alg: -257 },  // RSASSA-PKCS1-v1_5 (alg -257)
        ],
        authenticatorSelection: {
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

// start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 سرور در حال اجرا روی پورت ${PORT}`);
});
