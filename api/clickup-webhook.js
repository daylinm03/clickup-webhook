import crypto from "node:crypto";
import fetch from "cross-fetch";

const isDebug = () => process.env.DEBUG === "true";

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") return res.status(405).json({ ok: false, error: "Method not allowed" });

    // 1) Verify signature over RAW body
    const raw = await readRawBody(req);
    const secret = process.env.CLICKUP_WEBHOOK_SECRET;
    const sig = req.headers["x-signature"];
    if (!secret) return res.status(500).json({ ok: false, error: "Missing CLICKUP_WEBHOOK_SECRET" });

    const expected = crypto.createHmac("sha256", secret).update(raw).digest("hex");
    if (sig !== expected) return res.status(401).json({ ok: false, error: "Invalid signature" });

    // 2) Parse payload
    let body;
    try { body = JSON.parse(raw); } catch { return res.status(400).json({ ok: false, error: "Invalid JSON" }); }

    const event  = body?.event;
    const taskId = body?.task_id || body?.task?.id || body?.payload?.task_id;
    let   listId = body?.list_id || body?.task?.list?.id || body?.payload?.list_id;
    const targetListId = process.env.TARGET_LIST_ID || null;

    if (isDebug()) console.log("event:", event, "taskId:", taskId, "listId:", listId);

    // If we care about list filtering and listId is missing, fetch it once
    if (!listId && targetListId && taskId) {
      listId = await getListIdForTask(taskId);
      if (isDebug()) console.log("fetched listId:", listId);
    }

    if (targetListId && String(listId) !== String(targetListId)) {
      return res.status(200).json({ ok: true, skipped: "Different list" });
    }

    // 3) Actions
    if (event === "taskCreated" && taskId) {
      const fieldId = process.env.TO_BE_INVOICED_FIELD_ID;
      if (!fieldId) return res.status(500).json({ ok: false, error: "Missing TO_BE_INVOICED_FIELD_ID" });

      const ok = await setDateField(taskId, fieldId, Date.now());
      return res.status(200).json({ ok, did: ok ? "set date" : "failed", taskId });
    }

    // No-op for unhandled events
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: e.message });
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
  } catch { return undefined; }
}

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
