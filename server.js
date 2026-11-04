const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");

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

// Initialize database without deleting existing data.
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

    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS is_banned BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS ban_reason TEXT,
      ADD COLUMN IF NOT EXISTS ban_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ;

    ALTER TABLE reward_codes
      ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 0;
  `);
}

function createToken(user) {
  return jwt.sign(
    {
      sub: String(user.id),
      role: user.role,
      username: user.username
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";

  try {
    if (!token) throw new Error("Missing token");
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    if (
      error.name === "JsonWebTokenError" ||
      error.name === "TokenExpiredError" ||
      error.message === "Missing token"
    ) {
      return res.status(401).json({
        error: "لطفاً دوباره وارد حساب شوید."
      });
    }
    next(error);
  }
}

async function requireActivePlayer(req, res, next) {
  try {
    if (req.auth?.role !== "player") {
      return res.status(403).json({
        error: "حساب بازیکن لازم است."
      });
    }

    const result = await pool.query(
      "SELECT is_banned, ban_reason, ban_expires_at FROM players WHERE id = $1",
      [req.auth.sub]
    );

    const player = result.rows[0];

    if (!player) {
      return res.status(401).json({
        error: "حساب بازیکن پیدا نشد."
      });
    }

    if (
      player.is_banned &&
      player.ban_expires_at &&
      new Date(player.ban_expires_at).getTime() <= Date.now()
    ) {
      await pool.query(
        `UPDATE players
         SET is_banned = FALSE,
             ban_reason = NULL,
             ban_expires_at = NULL,
             banned_at = NULL
         WHERE id = $1`,
        [req.auth.sub]
      );
      return next();
    }

    if (player.is_banned) {
      return res.status(403).json({
        error: "حساب شما مسدود شده است.",
        banned: true,
        banType: player.ban_expires_at ? "temporary" : "permanent",
        reason: player.ban_reason || "دلیلی ثبت نشده است.",
        banReason: player.ban_reason || "دلیلی ثبت نشده است.",
        expiresAt: player.ban_expires_at,
        banExpiresAt: player.ban_expires_at,
        player: publicPlayer(player)
      });
    }

    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({
      error: "دسترسی مدیر لازم است."
    });
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
    lastLogin: player.last_login,
    isBanned: player.is_banned || false,
    banReason: player.ban_reason || null,
    banExpiresAt: player.ban_expires_at || null,
    bannedAt: player.banned_at || null
  };
}

function safeTextEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function normalizeRewardCode(value) {
  return String(value || "")
    .trim()
    .normalize("NFC")
    .toUpperCase();
}

app.get("/", (req, res) => {
  res.json({
    name: "Bozorgshahr Server",
    status: "online",
    version: "1.3.0"
  });
});

app.get("/health", async (req, res, next) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected"
    });
  } catch (error) {
    next(error);
  }
});

// Player registration
app.post("/api/register", async (req, res, next) => {
  try {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const displayName = String(
      req.body.displayName || username
    ).trim();

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
      `INSERT INTO players
       (username, password_hash, display_name)
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
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM players WHERE username = $1",
      [username]
    );

    const player = result.rows[0];

    if (
      !player ||
      !(await bcrypt.compare(password, player.password_hash))
    ) {
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
    !safeTextEqual(username, ADMIN_USERNAME) ||
    !safeTextEqual(password, ADMIN_PASSWORD)
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
      return res.status(403).json({
        error: "حساب بازیکن لازم است."
      });
    }

    const result = await pool.query(
      "SELECT * FROM players WHERE id = $1",
      [req.auth.sub]
    );

    if (!result.rows[0]) {
      return res.status(404).json({
        error: "بازیکن پیدا نشد."
      });
    }

    res.json({
      player: publicPlayer(result.rows[0])
    });
  } catch (error) {
    next(error);
  }
});

// Save live player progress
app.put(
  "/api/me/game-data",
  requireAuth,
  requireActivePlayer,
  async (req, res, next) => {
    try {
      if (req.auth.role !== "player") {
        return res.status(403).json({
          error: "حساب بازیکن لازم است."
        });
      }

      const gameData = req.body.gameData;

      if (
        !gameData ||
        typeof gameData !== "object" ||
        Array.isArray(gameData)
      ) {
        return res.status(400).json({
          error: "اطلاعات بازی معتبر نیست."
        });
      }

      const intValue = (key, min, max = Number.MAX_SAFE_INTEGER) => {
        if (!Object.prototype.hasOwnProperty.call(gameData, key)) {
          return null;
        }

        const n = Number(gameData[key]);

        if (!Number.isSafeInteger(n)) return null;

        return Math.min(max, Math.max(min, n));
      };

      const coins = intValue("coins", 0);
      const level = intValue("level", 1);
      const hunger = intValue("hunger", 0, 100);
      const energy = intValue("energy", 0, 100);

      const playerName = typeof gameData.playerName === "string"
        ? gameData.playerName.trim().replace(/\s+/g, " ").slice(0, 18)
        : "";

      const cleanData = { ...gameData };

      for (const key of [
        "coins",
        "level",
        "hunger",
        "energy",
        "playerName"
      ]) {
        delete cleanData[key];
      }

      const result = await pool.query(
        `UPDATE players SET
           game_data = COALESCE(game_data, '{}'::jsonb) || $1::jsonb ||
             jsonb_strip_nulls(jsonb_build_object(
               'coins', $2::bigint,
               'level', $3::integer,
               'hunger', $4::integer,
               'energy', $5::integer,
               'playerName', NULLIF($6, '')
             )),
           coins = COALESCE($2::bigint, coins),
           level = COALESCE($3::integer, level),
           hunger = COALESCE($4::integer, hunger),
           energy = COALESCE($5::integer, energy),
           display_name = CASE
             WHEN length($6) BETWEEN 1 AND 18 THEN $6
             ELSE display_name
           END
         WHERE id = $7
         RETURNING *`,
        [
          JSON.stringify(cleanData),
          coins,
          level,
          hunger,
          energy,
          playerName,
          req.auth.sub
        ]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      res.json({
        player: publicPlayer(result.rows[0])
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: dashboard statistics
app.get(
  "/api/admin/stats",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT
          (SELECT COUNT(*) FROM players) AS total_players,
          (SELECT COUNT(*) FROM players
            WHERE is_banned = TRUE
            AND (ban_expires_at IS NULL OR ban_expires_at > NOW())
          ) AS banned_players,
          (SELECT COUNT(*) FROM reward_codes) AS total_reward_codes,
          (SELECT COUNT(*) FROM reward_codes
            WHERE active = TRUE
          ) AS active_reward_codes
      `);

      res.json({
        stats: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: list players
app.get(
  "/api/admin/players",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        "SELECT * FROM players ORDER BY created_at DESC LIMIT 500"
      );

      res.json({
        players: result.rows.map(publicPlayer)
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: search one player by username
app.get(
  "/api/admin/players/:username",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        "SELECT * FROM players WHERE username = $1",
        [String(req.params.username).toLowerCase()]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      res.json({
        player: publicPlayer(result.rows[0])
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: edit a player's game values
app.patch(
  "/api/admin/players/:id",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const allowed = [
        "displayName",
        "coins",
        "level",
        "score",
        "hunger",
        "energy"
      ];

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
      const syncParts = [];

      for (const key of allowed) {
        if (!Object.prototype.hasOwnProperty.call(req.body, key)) {
          continue;
        }

        let value = req.body[key];

        if (key === "displayName") {
          value = String(value || "").trim().slice(0, 18);

          if (!value) {
            return res.status(400).json({
              error: "نام نمایشی معتبر نیست."
            });
          }
        } else {
          value = Number(value);

          if (!Number.isSafeInteger(value) || value < 0) {
            return res.status(400).json({
              error: "مقدار عددی معتبر نیست."
            });
          }

          if (key === "level") value = Math.max(1, value);
          if (key === "hunger" || key === "energy") {
            value = Math.min(100, value);
          }
        }

        values.push(value);
        updates.push(`${fields[key]} = $${values.length}`);

        syncParts.push(`'${key === "displayName" ? "playerName" : key}', $${values.length}`);
      }

      if (!updates.length) {
        return res.status(400).json({
          error: "هیچ مقداری برای تغییر ارسال نشده است."
        });
      }

      const id = req.params.id;
      values.push(id);

      let query;

      if (syncParts.length) {
        query = `
          UPDATE players
          SET ${updates.join(", ")},
              game_data = COALESCE(game_data, '{}'::jsonb) ||
                jsonb_build_object(${syncParts.join(", ")})
          WHERE id = $${values.length}
          RETURNING *
        `;
      } else {
        query = `
          UPDATE players
          SET ${updates.join(", ")}
          WHERE id = $${values.length}
          RETURNING *
        `;
      }

      const result = await pool.query(query, values);

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      res.json({
        player: publicPlayer(result.rows[0])
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: ban or unban a player
app.patch(
  "/api/admin/players/:id/ban",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const banned = Boolean(req.body.banned);
      const reason = String(req.body.reason || "").trim().slice(0, 500);
      let expiresAt = null;

      if (banned && req.body.expiresAt) {
        const date = new Date(req.body.expiresAt);

        if (Number.isNaN(date.getTime()) || date.getTime() <= Date.now()) {
          return res.status(400).json({
            error: "زمان پایان مسدودیت معتبر نیست."
          });
        }

        expiresAt = date.toISOString();
      }

      const result = await pool.query(
        `UPDATE players
         SET is_banned = $1,
             ban_reason = CASE WHEN $1 THEN NULLIF($2, '') ELSE NULL END,
             ban_expires_at = CASE WHEN $1 THEN $3::timestamptz ELSE NULL END,
             banned_at = CASE WHEN $1 THEN NOW() ELSE NULL END
         WHERE id = $4
         RETURNING *`,
        [banned, reason, expiresAt, req.params.id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      res.json({
        player: publicPlayer(result.rows[0])
      });
    } catch (error) {
      next(error);
    }
  }
);
// Admin: unban a player
app.patch(
  "/api/admin/players/:id/unban",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `UPDATE players
         SET is_banned = FALSE,
             ban_reason = NULL,
             ban_expires_at = NULL,
             banned_at = NULL
         WHERE id = $1
         RETURNING *`,
        [req.params.id]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      res.json({
        player: publicPlayer(result.rows[0])
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: list reward codes
app.get(
  "/api/admin/reward-codes",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const result = await pool.query(`
        SELECT
          rc.*,
          (
            SELECT COUNT(*)
            FROM reward_redemptions rr
            WHERE rr.code_id = rc.id
          ) AS used_count
        FROM reward_codes rc
        ORDER BY rc.created_at DESC
      `);

      res.json({
        codes: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin: create reward code
app.post(
  "/api/admin/reward-codes",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const code = normalizeRewardCode(req.body.code);
      const coins = Number(req.body.coins);
      const maxUses = req.body.maxUses == null
        ? 0
        : Number(req.body.maxUses);

      let expiresAt = null;

      if (req.body.expiresAt) {
        const date = new Date(req.body.expiresAt);

        if (Number.isNaN(date.getTime())) {
          return res.status(400).json({
            error: "تاریخ انقضا معتبر نیست."
          });
        }

        expiresAt = date.toISOString();
      }

      if (!/^[A-Z0-9_-]{3,64}$/.test(code)) {
        return res.status(400).json({
          error: "کد باید بین ۳ تا ۶۴ نویسه و شامل حروف انگلیسی، عدد، خط تیره یا زیرخط باشد."
        });
      }

      if (!Number.isSafeInteger(coins) || coins < 1) {
        return res.status(400).json({
          error: "مقدار سکه معتبر نیست."
        });
      }

      if (!Number.isSafeInteger(maxUses) || maxUses < 0) {
        return res.status(400).json({
          error: "تعداد استفاده معتبر نیست."
        });
      }

      const result = await pool.query(
        `INSERT INTO reward_codes
         (code, coins, active, expires_at, max_uses)
         VALUES ($1, $2, TRUE, $3, $4)
         RETURNING *`,
        [code, coins, expiresAt, maxUses]
      );

      res.status(201).json({
        code: result.rows[0]
      });
    } catch (error) {
      if (error.code === "23505") {
        return res.status(409).json({
          error: "این کد قبلاً ساخته شده است."
        });
      }

      next(error);
    }
  }
);

// Admin: edit or deactivate reward code
app.patch(
  "/api/admin/reward-codes/:id",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const updates = [];
      const values = [];

      if (Object.prototype.hasOwnProperty.call(req.body, "coins")) {
        const coins = Number(req.body.coins);

        if (!Number.isSafeInteger(coins) || coins < 1) {
          return res.status(400).json({
            error: "مقدار سکه معتبر نیست."
          });
        }

        values.push(coins);
        updates.push(`coins = $${values.length}`);
      }

      if (Object.prototype.hasOwnProperty.call(req.body, "active")) {
        values.push(Boolean(req.body.active));
        updates.push(`active = $${values.length}`);
      }

      if (Object.prototype.hasOwnProperty.call(req.body, "maxUses")) {
        const maxUses = Number(req.body.maxUses);

        if (!Number.isSafeInteger(maxUses) || maxUses < 0) {
          return res.status(400).json({
            error: "تعداد استفاده معتبر نیست."
          });
        }

        values.push(maxUses);
        updates.push(`max_uses = $${values.length}`);
      }

      if (Object.prototype.hasOwnProperty.call(req.body, "expiresAt")) {
        let expiresAt = null;

        if (req.body.expiresAt) {
          const date = new Date(req.body.expiresAt);

          if (Number.isNaN(date.getTime())) {
            return res.status(400).json({
              error: "تاریخ انقضا معتبر نیست."
            });
          }

          expiresAt = date.toISOString();
        }

        values.push(expiresAt);
        updates.push(`expires_at = $${values.length}`);
      }

      if (!updates.length) {
        return res.status(400).json({
          error: "موردی برای تغییر ارسال نشده است."
        });
      }

      values.push(req.params.id);

      const result = await pool.query(
        `UPDATE reward_codes
         SET ${updates.join(", ")}
         WHERE id = $${values.length}
         RETURNING *`,
        values
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "کد جایزه پیدا نشد."
        });
      }

      res.json({
        code: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

// Player: redeem reward code
app.post(
  "/api/redeem",
  requireAuth,
  requireActivePlayer,
  async (req, res, next) => {
    const client = await pool.connect();

    try {
      if (req.auth.role !== "player") {
        return res.status(403).json({
          error: "حساب بازیکن لازم است."
        });
      }

      const code = normalizeRewardCode(req.body.code);

      if (!code) {
        return res.status(400).json({
          error: "کد جایزه را وارد کنید."
        });
      }

      await client.query("BEGIN");

      const codeResult = await client.query(
        `SELECT *
         FROM reward_codes
         WHERE code = $1
         FOR UPDATE`,
        [code]
      );

      const reward = codeResult.rows[0];

      if (!reward || !reward.active) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "کد جایزه معتبر نیست یا غیرفعال شده است."
        });
      }

      if (
        reward.expires_at &&
        new Date(reward.expires_at).getTime() <= Date.now()
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "مهلت استفاده از این کد به پایان رسیده است."
        });
      }

      const usedResult = await client.query(
        `SELECT COUNT(*) AS count
         FROM reward_redemptions
         WHERE code_id = $1`,
        [reward.id]
      );

      const usedCount = Number(usedResult.rows[0].count);

      if (reward.max_uses > 0 && usedCount >= reward.max_uses) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error: "ظرفیت استفاده از این کد تکمیل شده است."
        });
      }

      const alreadyUsed = await client.query(
        `SELECT 1
         FROM reward_redemptions
         WHERE player_id = $1 AND code_id = $2`,
        [req.auth.sub, reward.id]
      );

      if (alreadyUsed.rows.length > 0) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error: "شما قبلاً از این کد استفاده کرده‌اید."
        });
      }

      await client.query(
        `INSERT INTO reward_redemptions
         (player_id, code_id)
         VALUES ($1, $2)`,
        [req.auth.sub, reward.id]
      );

      const playerResult = await client.query(
        `UPDATE players
         SET coins = coins + $1
         WHERE id = $2
         RETURNING *`,
        [reward.coins, req.auth.sub]
      );

      if (!playerResult.rows[0]) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      await client.query("COMMIT");

      res.json({
        message: "کد با موفقیت ثبت شد.",
        coinsAdded: reward.coins,
        player: publicPlayer(playerResult.rows[0])
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      next(error);
    } finally {
      client.release();
    }
  }
);

// Global error handler
app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "خطای داخلی سرور رخ داده است."
  });
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(`Bozorgshahr server listening on ${PORT}`);
    });
  } catch (error) {
    console.error("Could not start server:", error);
    process.exit(1);
  }
}

startServer();
