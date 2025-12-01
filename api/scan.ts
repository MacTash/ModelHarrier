import type { VercelRequest, VercelResponse } from "@vercel/node";
import runProbe from "./probe";

const HF_API_BASE = "https://huggingface.co/api/models";

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const { modelId } = req.query;

        if (!modelId || typeof modelId !== "string") {
            res.status(400).json({ error: "modelId query is required" });
            return;
        }

        const hfResp = await fetch(`${HF_API_BASE}/${encodeURIComponent(modelId)}`);
        if (!hfResp.ok) {
            const status = hfResp.status;
            const message = status === 404 ? "Model not found on HuggingFace" : hfResp.statusText;
            res.status(status).json({ error: message });
            return;
        }

        const hfData = await hfResp.json();

        // Normalize HuggingFace model metadata
        const normalized = {
            ...hfData,
            cardData: hfData.cardData || {},
            tags: Array.isArray(hfData.tags) ? hfData.tags : [],
            siblings: Array.isArray(hfData.siblings) ? hfData.siblings : [],
        };

        // Run behavioral Red Team probing
        const redTeam = await runProbe({
            method: "GET",
            query: { modelId },
        } as any, {
            status: () => ({ json: (d: any) => d }),
            json: (d: any) => d,
        } as any);

        res.status(200).json({
            model: normalized,
            redTeamInsights: redTeam,
        });
    } catch (err: any) {
        console.error("Scan error:", err);
        res.status(500).json({ error: err.message || "Internal scan error" });
    }
}
