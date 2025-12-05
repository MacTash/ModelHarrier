import type { VercelRequest, VercelResponse } from "@vercel/node";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    res.setHeader('Access-Control-Allow-Origin', '*');

    try {
        // Try multiple ways to get modelId
        let modelId: string | string[] | undefined = req.query.modelId;

        // If query parsing fails, try parsing URL manually
        if (!modelId && req.url) {
            const url = new URL(req.url, `https://${req.headers.host}`);
            const parsed = url.searchParams.get('modelId');
            if (parsed) modelId = parsed;
        }

        if (!modelId || typeof modelId !== "string") {
            return res.status(400).json({
                error: "modelId query is required",
                debug: {
                    query: req.query,
                    url: req.url,
                    method: req.method
                }
            });
        }

        const url = `${HF_API_BASE}/${encodeURIComponent(modelId)}?full=true`;

        const response = await fetch(url, {
            headers: { "Accept": "application/json" },
        });

        if (!response.ok) {
            const status = response.status;
            let message = response.statusText || `HTTP ${status}`;

            if (status === 404) message = "Model not found on HuggingFace";
            else if (status === 429) message = "Rate limited. Try again.";

            return res.status(status).json({ error: message });
        }

        const data: any = await response.json();

        const normalized = {
            modelId: data.modelId || data.id || modelId,
            author: data.author || modelId.split('/')[0] || 'Unknown',
            cardData: data.cardData || {},
            tags: data.tags || [],
            siblings: data.siblings || [],
            downloads: data.downloads || 0,
            likes: data.likes || 0,
            library_name: data.library_name || data.pipeline_tag || 'Unknown',
            lastModified: data.lastModified || data.createdAt || new Date().toISOString(),
        };

        return res.status(200).json(normalized);

    } catch (err: any) {
        console.error("API Error:", err);
        return res.status(500).json({ error: err?.message || "Internal server error" });
    }
}
