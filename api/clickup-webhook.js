import crypto from "node:crypto";
import fetch from "cross-fetch";

/**
 * ENV to add in Vercel → Project → Settings → Environment Variables:
 * - CLICKUP_TOKEN
 * - CLICKUP_WEBHOOK_SECRET         (paste the secret you get back when you create the webhook)
 * - CLICKUP_TEAM_ID                (numeric)
 * - TARGET_LIST_ID                 (optional)
 * - TO_BE_INVOICED_FIELD_ID        (UUID of your Date custom field)
 */

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: "Method not allowed" });
    return;
  }

  try {
    const raw = await readRawBody(req);
    const signatureHeader = req.headers["x-signature"];
    const secret = process.env.CLICKUP_WEBHOOK_SECRET;

    if (!secret) {
      res.status(500).json({ ok: false, error: "Missing CLICKUP_WEBHOOK_SECRET" });
      return;
    }

    // Verify HMAC of the raw body
    const expected = crypto.createHmac("sha256", secret).update(raw).digest("hex");
    if (signatureHeader !== expected) {
      res.status(401).json({ ok: false, error: "Invalid signature" });
      return;
    }

    const body = JSON.parse(raw);
    const event = body?.event;
    const taskId = body?.task_id;
    const listId = body?.list_id || body?.task?.list?.id;
    const targetListId = process.env.TARGET_LIST_ID;

    if (targetListId && String(listId) !== String(targetListId)) {
      res.status(200).json({ ok: true, skipped: "Different list" });
      return;
    }

    if (event === "taskCreated" && taskId) {
      const fieldId = process.env.TO_BE_INVOICED_FIELD_ID;
      if (fieldId) {
        const nowMs = Date.now();
        const ok = await setCustomFieldValue(taskId, fieldId, nowMs);
        res.status(200).json({ ok, action: "set To-Be-Invoiced Date", taskId, value: nowMs });
        return;
      }
    }

    res.status(200).json({ ok: true, received: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err?.message || "Unknown error" });
  }
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
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
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ value }) // Date field expects epoch ms
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => "");
    console.error("Set CF failed:", r.status, txt);
    return false;
  }
  return true;
}
