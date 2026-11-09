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

// تنظیمات شرکت
const WORK_MAX_USES = 20;
const WORK_COOLDOWN_HOURS = 11;
const WORK_REWARD_COINS = 50;
const WORK_ENERGY_COST = 10;
const WORK_SCORE_REWARD = 70;

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

    -- افزودن محدودیت شرکت بدون حذف اطلاعات قبلی
    ALTER TABLE players
      ADD COLUMN IF NOT EXISTS work_used INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS work_reset_at TIMESTAMPTZ;
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
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

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
      `SELECT is_banned, ban_reason, ban_expires_at
       FROM players
       WHERE id = $1`,
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
        banType: player.ban_expires_at
          ? "temporary"
          : "permanent",
        reason: player.ban_reason || "دلیلی ثبت نشده است.",
        banReason: player.ban_reason || "دلیلی ثبت نشده است.",
        expiresAt: player.ban_expires_at,
        banExpiresAt: player.ban_expires_at
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
    bannedAt: player.banned_at || null,

    // اطلاعات محدودیت شرکت
    workUsed: Number(player.work_used || 0),
    workMaxUses: WORK_MAX_USES,
    workResetAt: player.work_reset_at || null
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
    version: "2.0.0"
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

// ثبت نام بازیکن
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

// ورود بازیکن
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

// ورود مدیر
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

// دریافت اطلاعات حساب
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
// ذخیره اطلاعات عمومی بازی
// مقادیر سکه، انرژی و امتیاز فقط از مسیرهای معتبر سرور تغییر می‌کنند.
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

      const cleanData = { ...gameData };

      // جلوگیری از بازنویسی مقادیر اقتصادی توسط فایل بازی
      for (const key of [
        "coins",
        "energy",
        "score",
        "workUsed",
        "workResetAt",
        "work_used",
        "work_reset_at"
      ]) {
        delete cleanData[key];
      }

      const levelValue = Object.prototype.hasOwnProperty.call(
        cleanData,
        "level"
      ) ? Number(cleanData.level) : null;

      const hungerValue = Object.prototype.hasOwnProperty.call(
        cleanData,
        "hunger"
      ) ? Number(cleanData.hunger) : null;

      if (
        levelValue !== null &&
        (!Number.isSafeInteger(levelValue) || levelValue < 1)
      ) {
        return res.status(400).json({
          error: "سطح بازیکن معتبر نیست."
        });
      }

      if (
        hungerValue !== null &&
        (!Number.isSafeInteger(hungerValue) ||
          hungerValue < 0 ||
          hungerValue > 100)
      ) {
        return res.status(400).json({
          error: "مقدار گرسنگی معتبر نیست."
        });
      }

      const playerName = typeof cleanData.playerName === "string"
        ? cleanData.playerName.trim()
            .replace(/\s+/g, " ")
            .slice(0, 18)
        : "";

      delete cleanData.playerName;

      const result = await pool.query(
        `UPDATE players
         SET game_data =
               COALESCE(game_data, '{}'::jsonb) || $1::jsonb,
             level = COALESCE($2::integer, level),
             hunger = COALESCE($3::integer, hunger),
             display_name = CASE
               WHEN length($4) BETWEEN 1 AND 18 THEN $4
               ELSE display_name
             END
         WHERE id = $5
         RETURNING *`,
        [
          JSON.stringify(cleanData),
          levelValue,
          hungerValue,
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

// =====================================================
// شرکت: انجام یک نوبت کار به صورت کاملاً کنترل‌شده در سرور
// =====================================================

app.post(
  "/api/work/do",
  requireAuth,
  requireActivePlayer,
  async (req, res, next) => {
    const client = await pool.connect();
    let transactionStarted = false;

    try {
      if (req.auth.role !== "player") {
        return res.status(403).json({
          error: "حساب بازیکن لازم است."
        });
      }

      await client.query("BEGIN");
      transactionStarted = true;

      // قفل بازیکن برای جلوگیری از درخواست‌های هم‌زمان
      const result = await client.query(
        `SELECT *
         FROM players
         WHERE id = $1
         FOR UPDATE`,
        [req.auth.sub]
      );

      const player = result.rows[0];

      if (!player) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      const nowResult = await client.query(
        "SELECT NOW() AS current_time"
      );

      const now = new Date(nowResult.rows[0].current_time);

      let used = Number(player.work_used || 0);
      let resetAt = player.work_reset_at
        ? new Date(player.work_reset_at)
        : null;

      // اگر زمان محدودیت تمام شده باشد، سهمیه آزاد می‌شود.
      if (
        used >= WORK_MAX_USES &&
        resetAt &&
        resetAt.getTime() <= now.getTime()
      ) {
        used = 0;
        resetAt = null;
      }

      // اگر محدودیت کامل شده و هنوز زمان آن تمام نشده باشد
      if (
        used >= WORK_MAX_USES &&
        resetAt &&
        resetAt.getTime() > now.getTime()
      ) {
        const remainingMs = resetAt.getTime() - now.getTime();

        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(429).json({
          error: "سهمیه کار شما تکمیل شده است.",
          code: "WORK_LIMIT_REACHED",
          workUsed: WORK_MAX_USES,
          workMaxUses: WORK_MAX_USES,
          workRemaining: 0,
          workResetAt: resetAt.toISOString(),
          remainingMilliseconds: remainingMs
        });
      }

      // محافظت در برابر وضعیت ناقص
      if (used >= WORK_MAX_USES) {
        used = 0;
        resetAt = null;
      }

      const energy = Number(player.energy);

      if (energy < WORK_ENERGY_COST) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(400).json({
          error: "انرژی کافی برای انجام کار ندارید.",
          code: "NOT_ENOUGH_ENERGY",
          energy,
          requiredEnergy: WORK_ENERGY_COST,
          workUsed: used,
          workMaxUses: WORK_MAX_USES,
          workRemaining: WORK_MAX_USES - used
        });
      }

      const newUsed = used + 1;

      // پس از بیستمین کار، محدودیت ۱۱ ساعته آغاز می‌شود.
      const newResetAt = newUsed >= WORK_MAX_USES
        ? new Date(
            now.getTime() +
            WORK_COOLDOWN_HOURS * 60 * 60 * 1000
          )
        : null;

      const update = await client.query(
        `UPDATE players
         SET coins = coins + $1,
             energy = energy - $2,
             score = score + $3,
             work_used = $4,
             work_reset_at = $5,
             game_data =
               COALESCE(game_data, '{}'::jsonb) ||
               jsonb_build_object(
                 'workUsed', $4::integer,
                 'workResetAt', $5::text
               )
         WHERE id = $6
         RETURNING *`,
        [
          WORK_REWARD_COINS,
          WORK_ENERGY_COST,
          WORK_SCORE_REWARD,
          newUsed,
          newResetAt ? newResetAt.toISOString() : null,
          req.auth.sub
        ]
      );

      await client.query("COMMIT");
      transactionStarted = false;

      const updatedPlayer = update.rows[0];

      res.json({
        success: true,
        message: "کار با موفقیت انجام شد.",
        coinsAdded: WORK_REWARD_COINS,
        energyUsed: WORK_ENERGY_COST,
        scoreAdded: WORK_SCORE_REWARD,
        workUsed: Number(updatedPlayer.work_used),
        workMaxUses: WORK_MAX_USES,
        workRemaining: Math.max(
          0,
          WORK_MAX_USES - Number(updatedPlayer.work_used)
        ),
        workResetAt: updatedPlayer.work_reset_at,
        player: publicPlayer(updatedPlayer)
      });
    } catch (error) {
      if (transactionStarted) {
        await client.query("ROLLBACK").catch(() => {});
      }

      next(error);
    } finally {
      client.release();
    }
  }
);

// دریافت وضعیت فعلی سهمیه شرکت
app.get(
  "/api/work/status",
  requireAuth,
  requireActivePlayer,
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT work_used, work_reset_at
         FROM players
         WHERE id = $1`,
        [req.auth.sub]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      let used = Number(result.rows[0].work_used || 0);
      let resetAt = result.rows[0].work_reset_at
        ? new Date(result.rows[0].work_reset_at)
        : null;

      const nowResult = await pool.query(
        "SELECT NOW() AS current_time"
      );

      const now = new Date(nowResult.rows[0].current_time);

      if (
        used >= WORK_MAX_USES &&
        resetAt &&
        resetAt.getTime() <= now.getTime()
      ) {
        const reset = await pool.query(
          `UPDATE players
           SET work_used = 0,
               work_reset_at = NULL,
               game_data =
                 COALESCE(game_data, '{}'::jsonb) ||
                 '{"workUsed":0,"workResetAt":null}'::jsonb
           WHERE id = $1
           RETURNING work_used, work_reset_at`,
          [req.auth.sub]
        );

        used = Number(reset.rows[0].work_used);
        resetAt = null;
      }

      res.json({
        workUsed: used,
        workMaxUses: WORK_MAX_USES,
        workRemaining: Math.max(0, WORK_MAX_USES - used),
        workResetAt: resetAt ? resetAt.toISOString() : null
      });
    } catch (error) {
      next(error);
    }
  }
);

// =====================================================
// مدیریت بازیکنان
// =====================================================

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

      res.json({ stats: result.rows[0] });
    } catch (error) {
      next(error);
    }
  }
);

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
        const index = values.length;

        if (key === "displayName") {
          updates.push(`display_name = $${index}::varchar(40)`);
        } else {
          updates.push(`${fields[key]} = $${index}`);
        }

        const jsonType = {
          displayName: "text",
          coins: "bigint",
          level: "integer",
          score: "bigint",
          hunger: "integer",
          energy: "integer"
        }[key];

        syncParts.push(
          `'${key === "displayName" ? "playerName" : key}', $${index}::${jsonType}`
        );
      }

      if (!updates.length) {
        return res.status(400).json({
          error: "هیچ مقداری برای تغییر ارسال نشده است."
        });
      }

      values.push(req.params.id);

      const result = await pool.query(
        `UPDATE players
         SET ${updates.join(", ")},
             game_data =
               COALESCE(game_data, '{}'::jsonb) ||
               jsonb_build_object(${syncParts.join(", ")})
         WHERE id = $${values.length}::bigint
         RETURNING *`,
        values
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

// مسدود یا آزادکردن بازیکن
app.patch(
  "/api/admin/players/:id/ban",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const banned = Boolean(req.body.banned);
      const reason = String(req.body.reason || "")
        .trim()
        .slice(0, 500);

      let expiresAt = null;

      if (banned && req.body.expiresAt) {
        const date = new Date(req.body.expiresAt);

        if (
          Number.isNaN(date.getTime()) ||
          date.getTime() <= Date.now()
        ) {
          return res.status(400).json({
            error: "زمان پایان مسدودیت معتبر نیست."
          });
        }

        expiresAt = date.toISOString();
      }

      const result = await pool.query(
        `UPDATE players
         SET is_banned = $1,
             ban_reason = CASE
               WHEN $1 THEN NULLIF($2, '')
               ELSE NULL
             END,
             ban_expires_at = CASE
               WHEN $1 THEN $3::timestamptz
               ELSE NULL
             END,
             banned_at = CASE
               WHEN $1 THEN NOW()
               ELSE NULL
             END
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

// =====================================================
// مدیریت کدهای جایزه
// =====================================================

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

      res.json({ codes: result.rows });
    } catch (error) {
      next(error);
    }
  }
);

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
          error: "کد جایزه معتبر نیست."
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

// ثبت کد جایزه توسط بازیکن
app.post(
  "/api/redeem",
  requireAuth,
  requireActivePlayer,
  async (req, res, next) => {
    const client = await pool.connect();
    let transactionStarted = false;

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
      transactionStarted = true;

      const codeResult = await client.query(
        `SELECT *
         FROM reward_codes
         WHERE code = $1
         FOR UPDATE`,
        [code]
      );

      const reward = codeResult.rows[0];

      if (!reward) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(404).json({
          error: "کد اشتباه است.",
          code: "INVALID_CODE"
        });
      }

      if (!reward.active) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(400).json({
          error: "کد منقضی شده است.",
          code: "EXPIRED_CODE"
        });
      }

      if (
        reward.expires_at &&
        new Date(reward.expires_at).getTime() <= Date.now()
      ) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(400).json({
          error: "کد منقضی شده است.",
          code: "EXPIRED_CODE"
        });
      }

      const usedResult = await client.query(
        `SELECT COUNT(*) AS count
         FROM reward_redemptions
         WHERE code_id = $1`,
        [reward.id]
      );

      const usedCount = Number(usedResult.rows[0].count);

      if (
        reward.max_uses > 0 &&
        usedCount >= reward.max_uses
      ) {
        await client.query("ROLLBACK");
        transactionStarted = false;

        return res.status(400).json({
          error: "ظرفیت استفاده از این کد تکمیل شده است.",
          code: "CODE_LIMIT_REACHED"
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
        transactionStarted = false;

        return res.status(409).json({
          error: "شما قبلاً از این کد استفاده کرده‌اید.",
          code: "ALREADY_USED"
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
        transactionStarted = false;

        return res.status(404).json({
          error: "بازیکن پیدا نشد."
        });
      }

      await client.query("COMMIT");
      transactionStarted = false;

      res.json({
        message: "کد با موفقیت ثبت شد.",
        coinsAdded: reward.coins,
        player: publicPlayer(playerResult.rows[0])
      });
    } catch (error) {
      if (transactionStarted) {
        await client.query("ROLLBACK").catch(() => {});
      }

      next(error);
    } finally {
      client.release();
    }
  }
);

// =====================================================
// مدیریت خطاها و راه‌اندازی سرور
// =====================================================

app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "خطای داخلی سرور رخ داده است."
  });
});

async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, () => {
      console.log(
        `Bozorgshahr server listening on ${PORT}`
      );
    });
  } catch (error) {
    console.error("Could not start server:", error);
    process.exit(1);
  }
}

startServer();
