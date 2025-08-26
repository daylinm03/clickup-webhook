import crypto from "node:crypto";
import fetch from "cross-fetch";

/**
 * ENV you must set in Vercel:
 * - CLICKUP_TOKEN               (your personal ClickUp API token or OAuth token)
 * - CLICKUP_WEBHOOK_SECRET      (returned when you create the webhook)
 * - CLICKUP_TEAM_ID             (numeric team/workspace id)
 * - TARGET_LIST_ID              (optional: only act on a specific list)
 * - TO_BE_INVOICED_FIELD_ID     (UUID of your Date custom field)
 */

export const config = {
  api: {
    bodyParser: false, // needed to read the raw body for HMAC verification
  },
};

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Method not allowed" });
    return;
  }

  try {
    const raw = await readRawBody(req);
    const signatureHeader = req.headers["x-signature"];

    // 1) Verify HMAC (hex digest of raw body with webhook secret)
    const secret = process.env.CLICKUP_WEBHOOK_SECRET;
    if (!secret) {
      console.error("Missing CLICKUP_WEBHOOK_SECRET");
      res.status(500).json({ ok: false, error: "Server not configured" });
      return;
    }

    const expected = crypto
      .createHmac("sha256", secret)
      .update(raw)
      .digest("hex");

    if (signatureHeader !== expected) {
      console.warn("Signature mismatch");
      res.status(401).json({ ok: false, error: "Invalid signature" });
      return;
    }

    // 2) Parse JSON *after* verifying
    const body = JSON.parse(raw);

    // Quick ACK to avoid retries; do work after shaping inputs.
    // (We’ll still await the core action here since it’s light.)
    const event = body?.event;
    const taskId = body?.task_id; // present for task events
    const listId = body?.list_id || body?.task?.list?.id;

    // Optional: only act for a specific list
    const targetListId = process.env.TARGET_LIST_ID;
    if (targetListId && String(listId) !== String(targetListId)) {
      res.status(200).json({ ok: true, skipped: "Different list" });
      return;
    }

    if (event === "taskCreated" && taskId) {
      // Example automation: set a Date custom field to "now"
      const fieldId = process.env.TO_BE_INVOICED_FIELD_ID; // Date CF (UUID)
      if (fieldId) {
        const nowMs = Date.now();
        const ok = await setCustomFieldValue(taskId, fieldId, nowMs);
        res.status(200).json({ ok, action: "set To-Be-Invoiced Date", taskId, value: nowMs });
        return;
      }
    }

    // Add more handlers as you need:
    // if (event === "taskUpdated") { ... }
    // if (event === "taskTimeTrackedUpdated") { ... }

    res.status(200).json({ ok: true, received: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err?.message || "Unknown error" });
  }
}

async function readRawBody(req) {
  return await new Promise((resolve, reject) => {
    try {
      const chunks = [];
      req.on("data", (c) => chunks.push(Buffer.from(c)));
      req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      req.on("error", reject);
    } catch (e) {
      reject(e);
    }
  });
}

async function setCustomFieldValue(taskId, fieldId, value) {
  const token = process.env.CLICKUP_TOKEN;
  if (!token) throw new Error("Missing CLICKUP_TOKEN");

  const url = `https://api.clickup.com/api/v2/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(fieldId)}`;
  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Authorization": token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ value }), // Date fields expect epoch ms
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.error("Set CF failed:", r.status, txt);
    return false;
  }
  return true;
}
