// api/clickup-webhook.js
import crypto from "node:crypto";
import fetch from "cross-fetch";

// Optional: set DEBUG="true" in Vercel envs to see extra logs
const isDebug = () => process.env.DEBUG === "true";

// Optional (recommended): configure these in Vercel envs; else fallback to literals
const SECUNDA_LIST_ID = process.env.SECUNDA_LIST_ID || "901205280473";
const JOB_TRACKER_LIST_ID = process.env.JOB_TRACKER_LIST_ID || "901211501276";

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ ok: false, error: "Method not allowed" });
    }

    // 1) Verify signature over RAW body (required for ClickUp webhooks)
    const raw = await readRawBody(req);
    const secret = process.env.CLICKUP_WEBHOOK_SECRET;
    const sig = req.headers["x-signature"];
    if (!secret) return res.status(500).json({ ok: false, error: "Missing CLICKUP_WEBHOOK_SECRET" });

    const expected = crypto.createHmac("sha256", secret).update(raw).digest("hex");
    if (sig !== expected) return res.status(401).json({ ok: false, error: "Invalid signature" });

    // 2) Parse payload after verifying
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return res.status(400).json({ ok: false, error: "Invalid JSON" });
    }

    const event  = body?.event;
    const taskId = body?.task_id || body?.task?.id || body?.payload?.task_id;
    let   listId = body?.list_id || body?.task?.list?.id || body?.payload?.list_id;
    const targetListId = process.env.TARGET_LIST_ID || null;

    if (isDebug()) console.log("event:", event, "taskId:", taskId, "listId:", listId);

    // PATCH: always resolve listId if missing so our rules can run
    if (!listId && taskId) {
      listId = await getListIdForTask(taskId);
      if (isDebug()) console.log("resolved listId via task lookup:", listId);
    }

    // Optional list filter: if set and mismatch, politely skip
    if (targetListId && String(listId) !== String(targetListId)) {
      return res.status(200).json({ ok: true, skipped: "Different list" });
    }

    // 3) Actions
    if (event === "taskCreated" && taskId) {
      const actions = {};

      // A) If created in Secunda Design, also attach to Job Tracker (like "Add to another List")
      if (String(listId) === String(SECUNDA_LIST_ID)) {
        const linked = await addTaskToList(JOB_TRACKER_LIST_ID, taskId);
        actions.addedToJobTracker = linked;
        if (isDebug()) console.log("added to Job Tracker:", linked);
      }

      // B) Stamp To-Be-Invoiced Date+Time (Date field expects epoch ms)
      const fieldId = process.env.TO_BE_INVOICED_FIELD_ID;
      if (fieldId) {
        const stamped = await setDateField(taskId, fieldId, Date.now());
        actions.dateStamped = stamped;
      }

      return res.status(200).json({ ok: true, taskId, listId, actions });
    }

    // No-op for unhandled events
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
  }
}

/** Read raw request body (needed for HMAC verification) */
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Resolve a task's list id (used when webhook payload omits list_id) */
async function getListIdForTask(taskId) {
  try {
    const token = process.env.CLICKUP_TOKEN;
    if (!token) return undefined;
    const r = await fetch(`https://api.clickup.com/api/v2/task/${encodeURIComponent(taskId)}`, {
      headers: { Authorization: token }
    });
    if (!r.ok) return undefined;
    const t = await r.json();
    return t?.list?.id;
  } catch {
    return undefined;
  }
}

/** Add an existing task to another list (ClickUp "Tasks in Multiple Lists" feature) */
async function addTaskToList(targetListId, taskId) {
  const token = process.env.CLICKUP_TOKEN;
  const url = `https://api.clickup.com/api/v2/list/${encodeURIComponent(targetListId)}/task/${encodeURIComponent(taskId)}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { Authorization: token }
  });
  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.error("Add to list failed:", r.status, txt);
    return false;
  }
  return true;
}

/** Set a Date custom field (value must be epoch milliseconds) */
async function setDateField(taskId, fieldId, epochMs) {
  const token = process.env.CLICKUP_TOKEN;
  if (!token) throw new Error("Missing CLICKUP_TOKEN");

  const url = `https://api.clickup.com/api/v2/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(fieldId)}`;
  const r = await fetch(url, {
    method: "POST",
    headers: { Authorization: token, "Content-Type": "application/json" },
    body: JSON.stringify({ value: epochMs })
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.error("Set CF failed:", r.status, txt);
    return false;
  }
  return true;
}
