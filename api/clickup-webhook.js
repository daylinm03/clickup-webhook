// api/clickup-webhook.js
import crypto from "node:crypto";
import fetch from "cross-fetch";

/** ===== Config & helpers ===== */
const DEBUG = process.env.DEBUG === "true";
const dlog  = (...a) => { if (DEBUG) console.log(...a); };
const slog  = (...a) => console.log(...a); // concise summary (always logs)

// Required secrets
const SECRET = process.env.CLICKUP_WEBHOOK_SECRET;
const TOKEN  = process.env.CLICKUP_TOKEN;

// Target list (Job Tracker)
const JOB_TRACKER_LIST_ID = process.env.JOB_TRACKER_LIST_ID || "901211501276";

// Date field to set on taskCreated (epoch ms)
const DATE_FIELD_ID = process.env.DATE_FIELD_ID || "5497bac6-d964-434e-af6e-706995976c07";

// Optional global filter (usually leave unset)
const TARGET_LIST_ID = process.env.TARGET_LIST_ID || null;

/** Source lists (env > fallback) */
const SECUNDA_LIST_ID               = process.env.SECUNDA_LIST_ID               || "901205280473";
const SECUNDA_INJECTIONS_LIST_ID    = process.env.SECUNDA_INJECTIONS_LIST_ID    || "901207177834";
const VAAL_LIST_ID                  = process.env.VAAL_LIST_ID                  || "901207526223";
const VAAL_INJECTIONS_LIST_ID       = process.env.VAAL_INJECTIONS_LIST_ID       || "901211448490";
const MPUMALANGA_DESIGNS_LIST_ID    = process.env.MPUMALANGA_DESIGNS_LIST_ID    || "901208363216";
const MPUMALANGA_INJECTIONS_LIST_ID = process.env.MPUMALANGA_INJECTIONS_LIST_ID || "901208363209";
const SSSA_DESIGNS_LIST_ID          = process.env.SSSA_DESIGNS_LIST_ID          || "901211315230";
const TCO_DESIGNS_LIST_ID           = process.env.TCO_DESIGNS_LIST_ID           || "901207432882";
const INTLOCAL_DESIGNS_LIST_ID      = process.env.INTLOCAL_DESIGNS_LIST_ID      || "901208400956";
const NCOC_LIST_ID                  = process.env.NCOC_LIST_ID                  || "901213147743";
const TASK_HOURS_ENG_FIELD_ID  = "27043ad1-2437-4201-8d89-a4a306ff9c5b";
const TASK_HOURS_DRFT_FIELD_ID = "44bed523-6bfd-448e-be47-3c5dd4f84cf4";
const DEFAULT_HOURS_VALUE      = "STD:0-OT1:0-OT2:0";

/** Entity dropdown field + option IDs (env > fallback) */
const ENTITY_FIELD_ID = process.env.ENTITY_FIELD_ID || "af029e47-83b3-4172-9858-2402b111f5d6";
const ENTITY_OPT = {
  "SASOL SECUNDA": process.env.ENTITY_OPT_SASOL_SECUNDA || "db79f2a8-c910-4b3b-9139-f253f95c0e33",
  "VAAL":          process.env.ENTITY_OPT_VAAL          || "6625e76c-5ea0-4830-899b-af45e26c1036",
  "TCO":           process.env.ENTITY_OPT_TCO           || "26bfe07f-d208-4057-a84e-bc22b0e7bade",
  "MPUMALANGA":    process.env.ENTITY_OPT_MPUMALANGA    || "2ed7499d-47b9-4474-91fc-eebe9396683d",
  "SSSA":          process.env.ENTITY_OPT_SSSA          || "9ff0171b-62f7-4218-a962-0c4a45f5abcd",
  "NCOC":          process.env.ENTITY_OPT_NCOC          || "4e4f5797-d3ab-44b6-84d9-f859baa14c26",
};

/** Map source list → which Entity to set */
const LIST_TO_ENTITY = new Map([
  [SECUNDA_LIST_ID,               "SASOL SECUNDA"],
  [SECUNDA_INJECTIONS_LIST_ID,    "SASOL SECUNDA"],
  [VAAL_LIST_ID,                  "VAAL"],
  [VAAL_INJECTIONS_LIST_ID,       "VAAL"],
  [MPUMALANGA_DESIGNS_LIST_ID,    "MPUMALANGA"],
  [MPUMALANGA_INJECTIONS_LIST_ID, "MPUMALANGA"],
  [SSSA_DESIGNS_LIST_ID,          "SSSA"],
  [TCO_DESIGNS_LIST_ID,           "TCO"],
  [NCOC_LIST_ID,                  "NCOC"],
]);

/** Lists that should ALWAYS attach to Job Tracker (even if no entity mapping) */
const ATTACH_SOURCE_LIST_IDS = new Set([
  ...Array.from(LIST_TO_ENTITY.keys()).map(String),
  String(INTLOCAL_DESIGNS_LIST_ID), // <- International Local Manufacture
]);

/** Unified ClickUp fetch helper */
async function cu(path, init = {}) {
  if (!TOKEN) throw new Error("Missing CLICKUP_TOKEN");
  const url = `https://api.clickup.com/api/v2${path}`;
  const headers = { Authorization: TOKEN, ...(init.body && { "Content-Type": "application/json" }), ...init.headers };
  const r = await fetch(url, { ...init, headers });
  const text = await r.text().catch(() => "");
  if (!r.ok) {
    if (DEBUG) console.error("ClickUp API error:", r.status, url, text?.slice(0, 600));
    return { ok: false, status: r.status, text };
  }
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { /* ignore */ }
  return { ok: true, status: r.status, json, text };
}

/** Raw body reader (needed for HMAC) */
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

    // 1) Verify HMAC over raw body
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

    dlog("event:", event, "taskId:", taskId, "listId:", listId);

    // Resolve listId if missing
    if (!listId && taskId) {
      const { ok, json } = await cu(`/task/${encodeURIComponent(taskId)}`);
      listId = ok ? json?.list?.id : undefined;
      dlog("resolved listId via task lookup:", listId);
    }

    // Optional filter
    if (TARGET_LIST_ID && String(listId) !== String(TARGET_LIST_ID)) {
      dlog("skipped due to TARGET_LIST_ID filter", { listId, TARGET_LIST_ID });
      return res.status(200).json({ ok: true, skipped: "Different list" });
    }

    /** ===== 3) Actions ===== */
    if (event === "taskCreated" && taskId) {
      let attached = false, dateStamped = false, entitySet = false, entityName = null;

      // 3A) Attach to Job Tracker if list is in the allow-list
      const listKey = String(listId);
      const entityForList = LIST_TO_ENTITY.get(listKey) || null;
      const shouldAttach  = ATTACH_SOURCE_LIST_IDS.has(listKey);

      dlog("shouldAttach?", shouldAttach, "entityForList:", entityForList, "listKey:", listKey);

      if (shouldAttach) {
        const add = await cu(`/list/${encodeURIComponent(JOB_TRACKER_LIST_ID)}/task/${encodeURIComponent(taskId)}`, { method: "POST" });
        attached = add.ok || add.status === 409; // 409 = already attached
        if (!attached) console.error("Add to Job Tracker failed:", { status: add.status, body: add.text?.slice(0, 600) });
      }

      // 3B) Stamp generic Date field
      if (DATE_FIELD_ID) {
        const stamp = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(DATE_FIELD_ID)}`, {
          method: "POST",
          body: JSON.stringify({ value: Date.now() })
        });
        dateStamped = stamp.ok;
        if (!stamp.ok) console.error("Date field set failed:", { status: stamp.status, body: stamp.text?.slice(0, 600) });
      }

      // 3C) Set Entity dropdown (only if mapping exists)
      if (entityForList) {
        const optionId = ENTITY_OPT[entityForList];
        if (optionId) {
          const set = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(ENTITY_FIELD_ID)}`, {
            method: "POST",
            body: JSON.stringify({ value: optionId }) // dropdown expects option id
          });
          entitySet = set.ok;
          entityName = entityForList;
          if (!set.ok) console.error("Entity set failed:", { status: set.status, body: set.text?.slice(0, 600) });
        } else {
          console.error("Missing option ID for entity:", entityForList);
        }
      }
      // 3D) Set default Task Hours fields if attached to Job Tracker
      let hoursSetEng = false, hoursSetDrft = false;
      if (attached) {
        const setEng = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(TASK_HOURS_ENG_FIELD_ID)}`, {
          method: "POST",
          body: JSON.stringify({ value: DEFAULT_HOURS_VALUE })
        });
        hoursSetEng = setEng.ok;
        if (!setEng.ok) console.error("Task Hours - ENG set failed:", { status: setEng.status, body: setEng.text?.slice(0, 600) });

        const setDrft = await cu(`/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(TASK_HOURS_DRFT_FIELD_ID)}`, {
          method: "POST",
          body: JSON.stringify({ value: DEFAULT_HOURS_VALUE })
        });
        hoursSetDrft = setDrft.ok;
        if (!setDrft.ok) console.error("Task Hours - DRFT set failed:", { status: setDrft.status, body: setDrft.text?.slice(0, 600) });
      }
      // **Single summary line**
      slog(
        `summary: event=taskCreated taskId=${taskId} listId=${listId} ` +
        `attached=${attached} dateStamped=${dateStamped} entitySet=${entitySet}` +
        (entityName ? ` entity="${entityName}"` : "") + `hoursSetEng=${hoursSetEng} hoursSetDrft=${hoursSetDrft}`

      );

      return res.status(200).json({ ok: true, taskId, listId, attached, dateStamped, entitySet, entityName });
    }

    return res.status(200).json({ ok: true }); // no-op for other events
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  }
}
