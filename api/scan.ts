import type { VercelRequest, VercelResponse } from "@vercel/node";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            res.status(400).json({ error: "modelId query is required" });
            return;
        }

        // Call Hugging Face model API
        const response = await fetch(`${HF_API_BASE}/${encodeURIComponent(modelId)}`);

        if (!response.ok) {
            const status = response.status;
            const message = status === 404 ? "Model not found on HuggingFace" : response.statusText;
            res.status(status).json({ error: message });
            return;
        }

        const data = await response.json();

        // Normalize a few fields so frontend logic is safer
        const normalized = {
            ...data,
            cardData: data.cardData || {},
            tags: Array.isArray(data.tags) ? data.tags : [],
            siblings: Array.isArray(data.siblings) ? data.siblings : [],
        };

        // Important: return HF-style data, NOT a custom report object
        res.status(200).json(normalized);
    } catch (err: any) {
        console.error("HF proxy error:", err);
        res.status(500).json({ error: err.message || "Internal error" });
    }
}
