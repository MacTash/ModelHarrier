import type { VercelRequest, VercelResponse } from "@vercel/node";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            res.status(400).json({ error: "modelId query is required" });
            return;
        }

        // Use full=true to get complete file listings and metadata
        // Add cache-busting headers to ensure fresh data for new models
        const response = await fetch(
            `${HF_API_BASE}/${encodeURIComponent(modelId)}?full=true`,
            {
                headers: {
                    "Accept": "application/json",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                },
            }
        );

        if (!response.ok) {
            const status = response.status;
            let message = response.statusText;

            if (status === 404) {
                message = "Model not found on HuggingFace. Check the model ID or try again in a few minutes for newly published models.";
            } else if (status === 429) {
                message = "Rate limited by HuggingFace. Please try again in a moment.";
            }

            res.status(status).json({ error: message });
            return;
        }

        const data = await response.json();

        // Normalize response to ensure consistent structure
        const normalized = {
            ...data,
            modelId: data.modelId || data.id || modelId,
            author: data.author || modelId.split('/')[0] || 'Unknown',
            cardData: data.cardData || {},
            tags: Array.isArray(data.tags) ? data.tags : [],
            siblings: Array.isArray(data.siblings) ? data.siblings : [],
            downloads: data.downloads || 0,
            likes: data.likes || 0,
            library_name: data.library_name || data.pipeline_tag || 'Unknown',
            lastModified: data.lastModified || data.createdAt || new Date().toISOString(),
        };

        // Set cache headers to allow brief caching but revalidate
        res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=300');
        res.status(200).json(normalized);
    } catch (err: any) {
        console.error("HF proxy error:", err);
        res.status(500).json({ error: err.message || "Internal error fetching model data" });
    }
}

