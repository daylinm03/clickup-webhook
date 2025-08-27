// api/clickup-webhook.js
import crypto from "node:crypto";
import fetch from "cross-fetch";

/** ===== Config & helpers ===== */
const DEBUG = process.env.DEBUG === "true";
const log   = (...a) => { if (DEBUG) console.log(...a); };

const SECRET = process.env.CLICKUP_WEBHOOK_SECRET;                          // required
const TOKEN  = process.env.CLICKUP_TOKEN;                                   // required for API calls

// List IDs (env > fallback)
const SECUNDA_LIST_ID      = process.env.SECUNDA_LIST_ID      || "901205280473";
const VAAL_LIST_ID         = process.env.VAAL_LIST_ID         || "901207526223"; // <— NEW
const JOB_TRACKER_LIST_ID  = process.env.JOB_TRACKER_LIST_ID  || "901211501276";

const TARGET_LIST_ID       = process.env.TARGET_LIST_ID || null;            // optional filter
const TO_BE_INVOICED_ID    = process.env.TO_BE_INVOICED_FIELD_ID || null;   // optional action

// Unified ClickUp fetch helper
async function cu(path, init = {}) {
  if (!TOKEN) throw new Error("Missing CLICKUP_TOKEN");
  const url = `https://api.clickup.com/api/v2${path}`;
  const headers = { Authorization: TOKEN, ...(init.body && { "Content-Type": "application/json" }), ...init.headers };
  const r = await fetch(url, { ...init, headers });
  const text = await r.text().catch(() => "");
  if (!r.ok) {
    if (DEBUG) console.error("ClickUp API error:", r.status, url, text?.slice(0, 500));
    return { ok: false, status: r.status, text };
  }
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { /* ignore */ }
  return { ok: true, status: r.status, json, text };
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end",  () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** ===== Main handler ===== */
export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method not allowed" });
    if (!SECRET)              return res.status(500).json({ ok: false, error: "Missing CLICKUP_WEBHOOK_SECRET" });

    // 1) Verify HMAC over RAW body
    const raw = await readRawBody(req);
    const sig = req.headers["x-signature"];
    const expected = crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
    if (sig !== expected) return res.status(401).json({ ok: false, error: "Invalid signature" });

    // 2) Parse payload
    let body;
    try { body = JSON.parse(raw); } catch { return res.status(400).json({ ok: false, error: "Invalid JSON" }); }

    const event  = body?.event;
    const taskId = body?.task_id || body?.task?.id || body?.payload?.task_id;
    let   listId = body?.list_id || body?.task?.list?.id || body?.payload?.list_id;

    log("event:", event, "taskId:", taskId, "listId:", listId);

    // Resolve listId if missing (so list-based rules can run)
    if (!listId && taskId) {
      const { ok, json } = await cu(`/task/${encodeURIComponent(taskId)}`);
      listId = ok ? json?.list?.id : undefined;
      log("resolved listId via task lookup:", listId);
    }

    // Optional filter by TARGET_LIST_ID
    if (TARGET_LIST_ID && String(listId) !== String(TARGET_LIST_ID)) {
      return res.status(200).json({ ok: true, skipped: "Different list" });
    }

    /** ===== 3) Actions ===== */
    if (event === "taskCreated" && taskId) {
      const actions = {};

      // A) If created in Secunda OR Vaal Design, attach to Job Tracker (multi-list)
      const shouldAttach =
        String(listId) === String(SECUNDA_LIST_ID) ||
        String(listId) === String(VAAL_LIST_ID);

      if (shouldAttach) {
        const add = await cu(`/list/${encodeURIComponent(JOB_TRACKER_LIST_ID)}/task/${encodeURIComponent(taskId)}`, { method: "POST" });
        actions.addedToJobTracker = add.ok;
        log("added to Job Tracker:", add.ok);
      }

      // B) Stamp To-Be-Invoiced with Date+Time (epoch ms)
      if (TO_BE_INVOICED_ID) {
        const stamp = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(TO_BE_INVOICED_ID)}`, {
          method: "POST",
          body: JSON.stringify({ value: Date.now() })
        });
        actions.dateStamped = stamp.ok;
      }

      return res.status(200).json({ ok: true, taskId, listId, actions });
    }

    // No-op for other events
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  }
}
