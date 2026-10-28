
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!DATABASE_URL || !JWT_SECRET || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
  console.error("Missing required server environment variables.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "disable"
    ? false
    : { rejectUnauthorized: false }
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(40) NOT NULL,
      coins BIGINT NOT NULL DEFAULT 100,
      level INTEGER NOT NULL DEFAULT 1,
      score BIGINT NOT NULL DEFAULT 0,
      hunger INTEGER NOT NULL DEFAULT 100,
      energy INTEGER NOT NULL DEFAULT 100,
      game_data JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_login TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS reward_codes (
      id BIGSERIAL PRIMARY KEY,
      code VARCHAR(64) UNIQUE NOT NULL,
      coins BIGINT NOT NULL DEFAULT 0,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reward_redemptions (
      player_id BIGINT NOT NULL REFERENCES players(id),
      code_id BIGINT NOT NULL REFERENCES reward_codes(id),
      redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (player_id, code_id)
    );
  `);
}

function createToken(user) {
  return jwt.sign(
    { sub: String(user.id), role: user.role, username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  try {
    if (!token) throw new Error("Missing token");
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "لطفاً دوباره وارد حساب شوید." });
  }
}

function requireAdmin(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({ error: "دسترسی مدیر لازم است." });
  }
  next();
}

function publicPlayer(player) {
  return {
    id: player.id,
    username: player.username,
    displayName: player.display_name,
    coins: player.coins,
    level: player.level,
    score: player.score,
    hunger: player.hunger,
    energy: player.energy,
    gameData: player.game_data,
    createdAt: player.created_at,
    lastLogin: player.last_login
  };
}

app.get("/", (req, res) => {
  res.json({
    name: "Bozorgshahr Server",
    status: "online",
    version: "1.0.0"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Player registration
app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");
    const displayName = String(req.body.displayName || username).trim();

    if (!/^[a-z0-9_]{3,24}$/.test(username)) {
      return res.status(400).json({
        error: "نام کاربری باید ۳ تا ۲۴ حرف انگلیسی، عدد یا زیرخط باشد."
      });
    }

    if (password.length < 10 || password.length > 72) {
      return res.status(400).json({
        error: "رمز عبور باید حداقل ۱۰ و حداکثر ۷۲ نویسه باشد."
      });
    }

    if (!displayName || displayName.length > 40) {
      return res.status(400).json({
        error: "نام داخل بازی معتبر نیست."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO players (username, password_hash, display_name)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [username, passwordHash, displayName]
    );

    const player = result.rows[0];
    res.status(201).json({
      token: createToken({
        id: player.id,
        username: player.username,
        role: "player"
      }),
      player: publicPlayer(player)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "این نام کاربری قبلاً ثبت شده است."
      });
    }
    next(error);
  }
});

// Player login
app.post("/api/login", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim().toLowerCase();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM players WHERE username = $1",
      [username]
    );

    const player = result.rows[0];

    if (!player || !(await bcrypt.compare(password, player.password_hash))) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    await pool.query(
      "UPDATE players SET last_login = NOW() WHERE id = $1",
      [player.id]
    );

    res.json({
      token: createToken({
        id: player.id,
        username: player.username,
        role: "player"
      }),
      player: publicPlayer(player)
    });
  } catch (error) {
    next(error);
  }
});

// Admin login
app.post("/api/admin/login", (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");

  if (
    username !== ADMIN_USERNAME ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "اطلاعات ورود مدیر اشتباه است."
    });
  }

  res.json({
    token: createToken({
      id: "admin",
      username: ADMIN_USERNAME,
      role: "admin"
    })
  });
});

// Current player's saved information
app.get("/api/me", requireAuth, async (req, res, next) => {
  try {
    if (req.auth.role !== "player") {
      return res.status(403).json({ error: "حساب بازیکن لازم است." });
    }

    const result = await pool.query(
      "SELECT * FROM players WHERE id = $1",
      [req.auth.sub]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "بازیکن پیدا نشد." });
    }

    res.json({ player: publicPlayer(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

// Save allowed game progress; never accept coins or level from the client.
app.put("/api/me/game-data", requireAuth, async (req, res, next) => {
  try {
    if (req.auth.role !== "player") {
      return res.status(403).json({ error: "حساب بازیکن لازم است." });
    }

    const gameData = req.body.gameData;
    if (!gameData || typeof gameData !== "object" ||
        Array.isArray(gameData)) {
      return res.status(400).json({ error: "اطلاعات بازی معتبر نیست." });
    }

    const result = await pool.query(
      `UPDATE players SET game_data = $1::jsonb
       WHERE id = $2 RETURNING *`,
      [JSON.stringify(gameData), req.auth.sub]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "بازیکن پیدا نشد." });
    }

    res.json({ player: publicPlayer(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

// Admin: list players
app.get("/api/admin/players", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT * FROM players
       ORDER BY created_at DESC
       LIMIT 500`
    );
    res.json({ players: result.rows.map(publicPlayer) });
  } catch (error) {
    next(error);
  }
});

// Admin: search one player by username
app.get("/api/admin/players/:username", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT * FROM players WHERE username = $1",
      [String(req.params.username).toLowerCase()]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "بازیکن پیدا نشد." });
    }

    res.json({ player: publicPlayer(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

// Admin: edit a player's game values
app.patch("/api/admin/players/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const allowed = ["displayName", "coins", "level", "score", "hunger", "energy"];
    const fields = {
      displayName: "display_name",
      coins: "coins",
      level: "level",
      score: "score",
      hunger: "hunger",
      energy: "energy"
    };

    const updates = [];
    const values = [];

    for (const key of allowed) {
      if (!Object.prototype.hasOwnProperty.call(req.body, key)) continue;

      let value = req.body[key];

      if (key === "displayName") {
        if (typeof value !== "string" || !value.trim() || value.length > 40) {
          return res.status(400).json({ error: "نام داخل بازی معتبر نیست." });
        }
        value = value.trim();
      } else {
        value = Number(value);
        if (!Number.isSafeInteger(value)) {
          return res.status(400).json({ error: "مقدار عددی معتبر نیست." });
        }
        if (key === "coins" && value < 0) {
          return res.status(400).json({ error: "سکه نمی‌تواند منفی باشد." });
        }
        if (key === "level" && value < 1) {
          return res.status(400).json({ error: "سطح باید حداقل ۱ باشد." });
        }
        if (["hunger", "energy"].includes(key) && (value < 0 || value > 100)) {
          return res.status(400).json({ error: "مقدار باید بین ۰ تا ۱۰۰ باشد." });
        }
      }

      values.push(value);
      updates.push(`${fields[key]} = $${values.length}`);
    }

    if (!updates.length) {
      return res.status(400).json({ error: "مقداری برای تغییر ارسال نشده است." });
    }

    values.push(req.params.id);

    const result = await pool.query(
      `UPDATE players SET ${updates.join(", ")}
       WHERE id = $${values.length} RETURNING *`,
      values
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "بازیکن پیدا نشد." });
    }

    res.json({ player: publicPlayer(result.rows[0]) });
  } catch (error) {
    next(error);
  }
});

// Admin: create or update a reward code
app.post("/api/admin/reward-codes", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const code = String(req.body.code || "").trim().toUpperCase();
    const coins = Number(req.body.coins);

    if (!/^[A-Z0-9_-]{3,64}$/.test(code) ||
        !Number.isSafeInteger(coins) || coins < 0) {
      return res.status(400).json({ error: "کد یا مقدار جایزه معتبر نیست." });
    }

    const result = await pool.query(
      `INSERT INTO reward_codes (code, coins)
       VALUES ($1, $2)
       ON CONFLICT (code) DO UPDATE
       SET coins = EXCLUDED.coins, active = TRUE
       RETURNING id, code, coins, active, created_at`,
      [code, coins]
    );

    res.status(201).json({ rewardCode: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Admin: list reward codes
app.get("/api/admin/reward-codes", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    const result = await pool.query(
      "SELECT id, code, coins, active, created_at FROM reward_codes ORDER BY id DESC"
    );
    res.json({ rewardCodes: result.rows });
  } catch (error) {
    next(error);
  }
});

// Admin: activate or deactivate a reward code
app.patch("/api/admin/reward-codes/:id", requireAuth, requireAdmin, async (req, res, next) => {
  try {
    if (typeof req.body.active !== "boolean") {
      return res.status(400).json({ error: "وضعیت فعال بودن معتبر نیست." });
    }

    const result = await pool.query(
      `UPDATE reward_codes SET active = $1
       WHERE id = $2
       RETURNING id, code, coins, active, created_at`,
      [req.body.active, req.params.id]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "کد پیدا نشد." });
    }

    res.json({ rewardCode: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Player: redeem a reward code once per account
app.post("/api/redeem", requireAuth, async (req, res, next) => {
  const client = await pool.connect();

  try {
    if (req.auth.role !== "player") {
      return res.status(403).json({ error: "حساب بازیکن لازم است." });
    }

    const code = String(req.body.code || "").trim().toUpperCase();
    if (!code || code.length > 64) {
      return res.status(400).json({ error: "کد معتبر نیست." });
    }

    await client.query("BEGIN");

    const codeResult = await client.query(
      "SELECT * FROM reward_codes WHERE code = $1 AND active = TRUE FOR UPDATE",
      [code]
    );

    const reward = codeResult.rows[0];
    if (!reward) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "کد جایزه معتبر نیست." });
    }

    const playerId = req.auth.sub;

    const used = await client.query(
      `INSERT INTO reward_redemptions (player_id, code_id)
       VALUES ($1, $2)
       ON CONFLICT DO NOTHING RETURNING player_id`,
      [playerId, reward.id]
    );

    if (!used.rowCount) {
      await client.query("ROLLBACK");
      return res.status(409).json({ error: "این کد قبلاً استفاده شده است." });
    }

    await client.query(
      "UPDATE players SET coins = coins + $1 WHERE id = $2",
      [reward.coins, playerId]
    );

    await client.query("COMMIT");
    res.json({ success: true, coinsAwarded: reward.coins });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    next(error);
  } finally {
    client.release();
  }
});

app.use((err, req, res, next) => {
  console.error("Request failed:", err.message);
  res.status(500).json({ error: "خطای داخلی سرور رخ داد." });
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Bozorgshahr server listening on ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error.message);
    process.exit(1);
  });
