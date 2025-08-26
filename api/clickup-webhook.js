import crypto from "node:crypto";
import fetch from "cross-fetch";

export default async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return res.status(405).json({ ok: false, error: "Method not allowed" });
    }

    const raw = await readRawBody(req);
    const secret = process.env.CLICKUP_WEBHOOK_SECRET;
    const sig = req.headers["x-signature"];

    if (!secret) return res.status(500).json({ ok: false, where: "config", error: "Missing CLICKUP_WEBHOOK_SECRET" });

    const expected = crypto.createHmac("sha256", secret).update(raw).digest("hex");
    if (sig !== expected) return res.status(401).json({ ok: false, where: "auth", error: "Invalid signature" });

    let body;
    try { body = JSON.parse(raw); } catch { return res.status(400).json({ ok: false, where: "parse", error: "Invalid JSON" }); }

    const event  = body?.event;
    const taskId = body?.task_id;
    const listId = body?.list_id || body?.task?.list?.id;
    const targetListId = process.env.TARGET_LIST_ID;

    // Surface what we got
    console.log("event:", event, "taskId:", taskId, "listId:", listId);

    if (targetListId && String(listId) !== String(targetListId)) {
      return res.status(200).json({ ok: true, skipped: "Different list", listId, targetListId });
    }

    if (event === "taskCreated" && taskId) {
      const fieldId = process.env.TO_BE_INVOICED_FIELD_ID;
      if (!fieldId) return res.status(500).json({ ok: false, where: "config", error: "Missing TO_BE_INVOICED_FIELD_ID" });

      const token = process.env.CLICKUP_TOKEN;
      if (!token) return res.status(500).json({ ok: false, where: "config", error: "Missing CLICKUP_TOKEN" });

      const url = `https://api.clickup.com/api/v2/task/${encodeURIComponent(taskId)}/field/${encodeURIComponent(fieldId)}`;
      const payload = { value: Date.now() }; // Date field expects epoch ms
      const r = await fetch(url, { method: "POST", headers: { Authorization: token, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const text = await r.text().catch(() => "");

      if (!r.ok) return res.status(502).json({ ok: false, where: "clickup", status: r.status, body: text, url, payload });

      return res.status(200).json({ ok: true, did: "set date", taskId });
    }

    return res.status(200).json({ ok: true, note: "No action for this event", event, taskId, listId });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, where: "handler", error: e.message });
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
