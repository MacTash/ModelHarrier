import type { VercelRequest, VercelResponse } from "@vercel/node";

const HF_API_BASE = "https://huggingface.co/api/models";

interface HFModelResponse {
    id?: string;
    modelId?: string;
    author?: string;
    cardData?: Record<string, unknown>;
    tags?: string[];
    siblings?: Array<{ rfilename: string }>;
    downloads?: number;
    likes?: number;
    library_name?: string;
    pipeline_tag?: string;
    lastModified?: string;
    createdAt?: string;
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            res.status(400).json({ error: "modelId query is required" });
            return;
        }

        const response = await fetch(
            `${HF_API_BASE}/${encodeURIComponent(modelId)}?full=true`,
            {
                headers: {
                    "Accept": "application/json",
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

        const data = (await response.json()) as HFModelResponse;

        const normalized = {
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

        res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=300');
        res.status(200).json(normalized);
    } catch (err) {
        console.error("HF proxy error:", err);
        const message = err instanceof Error ? err.message : "Internal error fetching model data";
        res.status(500).json({ error: message });
    }
}


