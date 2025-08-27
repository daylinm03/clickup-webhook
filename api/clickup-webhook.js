// api/clickup-webhook.js
import crypto from "node:crypto";
import fetch from "cross-fetch";

/** ===== Config & helpers ===== */
const DEBUG = process.env.DEBUG === "true";
const log   = (...a) => { if (DEBUG) console.log(...a); };

const SECRET = process.env.CLICKUP_WEBHOOK_SECRET;   // required
const TOKEN  = process.env.CLICKUP_TOKEN;            // required for API calls

// Target list to attach to (Job Tracker)
const JOB_TRACKER_LIST_ID = process.env.JOB_TRACKER_LIST_ID || "901211501276";

// Date field to set on taskCreated (NOT the To-Be-Invoiced field anymore)
const DATE_FIELD_ID = process.env.DATE_FIELD_ID || "5497bac6-d964-434e-af6e-706995976c07";

// Optional global filter, leave unset to react to all lists
const TARGET_LIST_ID = process.env.TARGET_LIST_ID || null;

// Source lists that should auto-attach to Job Tracker on taskCreated
const SECUNDA_LIST_ID                = process.env.SECUNDA_LIST_ID                || "901205280473";
const VAAL_LIST_ID                   = process.env.VAAL_LIST_ID                   || "901207526223";
const SECUNDA_INJECTIONS_LIST_ID     = process.env.SECUNDA_INJECTIONS_LIST_ID     || "901207177834";
const VAAL_INJECTIONS_LIST_ID        = process.env.VAAL_INJECTIONS_LIST_ID        || "901211448490";
const MPUMALANGA_DESIGNS_LIST_ID     = process.env.MPUMALANGA_DESIGNS_LIST_ID     || "901208363216";
const MPUMALANGA_INJECTIONS_LIST_ID  = process.env.MPUMALANGA_INJECTIONS_LIST_ID  || "901211504968";
const SSSA_DESIGNS_LIST_ID           = process.env.SSSA_DESIGNS_LIST_ID           || "901211315230";
const TCO_DESIGNS_LIST_ID            = process.env.TCO_DESIGNS_LIST_ID            || "901207432882";
const INTLOCAL_DESIGNS_LIST_ID       = process.env.INTLOCAL_DESIGNS_LIST_ID       || "901208400956";

// Build the source set (ignore any empty/undefined)
const SOURCE_LIST_IDS = [
  SECUNDA_LIST_ID,
  VAAL_LIST_ID,
  SECUNDA_INJECTIONS_LIST_ID,
  VAAL_INJECTIONS_LIST_ID,
  MPUMALANGA_DESIGNS_LIST_ID,
  MPUMALANGA_INJECTIONS_LIST_ID,
  SSSA_DESIGNS_LIST_ID,
  TCO_DESIGNS_LIST_ID,
  INTLOCAL_DESIGNS_LIST_ID,
].filter(Boolean);

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

// Raw body reader (needed for HMAC)
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
    if (!SECRET) return res.status(500).json({ ok: false, error: "Missing CLICKUP_WEBHOOK_SECRET" });

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

    // Optional global filter by TARGET_LIST_ID
    if (TARGET_LIST_ID && String(listId) !== String(TARGET_LIST_ID)) {
      return res.status(200).json({ ok: true, skipped: "Different list" });
    }

    /** ===== 3) Actions ===== */
    if (event === "taskCreated" && taskId) {
      const actions = {};

      // A) If created in any of the configured source lists, attach to Job Tracker (multi-list)
      const shouldAttach = SOURCE_LIST_IDS.some(id => String(listId) === String(id));
      if (shouldAttach) {
        const add = await cu(`/list/${encodeURIComponent(JOB_TRACKER_LIST_ID)}/task/${encodeURIComponent(taskId)}`, { method: "POST" });
        actions.addedToJobTracker = add.ok;
        log("added to Job Tracker:", add.ok);
      }

      // B) Set the generic Date field (epoch ms) — replaces previous To-Be-Invoiced date action
      if (DATE_FIELD_ID) {
        const stamp = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(DATE_FIELD_ID)}`, {
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
