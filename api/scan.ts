import type { VercelRequest, VercelResponse } from "@vercel/node";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            res.status(400).json({ error: "modelId query is required" });
            return;
        }

        const response = await fetch(`${HF_API_BASE}/${modelId}?full=true`);

        if (!response.ok) {
            const status = response.status;
            const message = status === 404 ? "Model not found on HuggingFace" : response.statusText;
            res.status(status).json({ error: message });
            return;
        }

        const data = await response.json() as any;

        const normalized = {
            ...data,
            cardData: data.cardData || {},
            tags: Array.isArray(data.tags) ? data.tags : [],
            siblings: Array.isArray(data.siblings) ? data.siblings : [],
        };

        res.status(200).json(normalized);
    } catch (err: any) {
        console.error("HF proxy error:", err);
        res.status(500).json({ error: err.message || "Internal error" });
    }
}
