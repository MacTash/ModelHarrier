import type { VercelRequest, VercelResponse } from "@vercel/node";
import runProbe from "./probe";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            return res.status(400).json({ error: "modelId query is required" });
        }

        const hfResp = await fetch(`${HF_API_BASE}/${encodeURIComponent(modelId)}`);

        if (!hfResp.ok) {
            const status = hfResp.status;
            const message = status === 404 ? "Model not found on HuggingFace" : hfResp.statusText;
            return res.status(status).json({ error: message });
        }

        const hfData = await hfResp.json();

        const normalized = {
            modelId,
            author: hfData.author || "Unknown",
            downloads: hfData.downloads || 0,
            likes: hfData.likes || 0,
            library_name: hfData.library_name || "Unknown",
            lastModified: hfData.lastModified || "",
            cardData: hfData.cardData || {},
            tags: Array.isArray(hfData.tags) ? hfData.tags : [],
            siblings: Array.isArray(hfData.siblings) ? hfData.siblings : [],
        };

        const redTeam = await runProbe({
            method: "GET",
            query: { modelId },
        } as any, {
            status: () => ({ json: (d: any) => d }),
            json: (d: any) => d,
        } as any);

        return res.status(200).json({
            ...normalized,
            redTeamInsights: redTeam
        });

    } catch (err: any) {
        console.error("Scan error:", err);
        return res.status(500).json({ error: err.message || "Internal scan error" });
    }
}
