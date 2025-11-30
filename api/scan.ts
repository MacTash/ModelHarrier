import type { VercelRequest, VercelResponse } from '@vercel/node';

const RISKY_EXTENSIONS = ['.pickle', '.pkl', '.joblib', '.dill', '.exe', '.bin', '.dll'];
const CODE_EXTENSIONS = ['.py', '.sh', '.bash', '.js'];
const SAFE_EXTENSIONS = ['.safetensors', '.onnx', '.tflite', '.json', '.txt', '.md'];

const SENSITIVE_DOMAINS = ['medical', 'finance', 'biometric', 'legal', 'surveillance'];

const REDTEAM_KEYWORDS = [
    'uncensored', 'no safety', 'jailbreak', 'do anything',
    'bypass restrictions', 'no guardrails', 'unrestricted',
    'unfiltered', 'no ethics', 'no censorship', 'no limits'
];

export default async function handler(req: VercelRequest, res: VercelResponse) {
    try {
        const modelId = req.query.modelId;
        if (!modelId || typeof modelId !== 'string') {
            res.status(400).json({ error: 'modelId query is required' });
            return;
        }

        const response = await fetch(`https://huggingface.co/api/models/${modelId}`);
        if (!response.ok) {
            const status = response.status;
            const message = status === 404 ? 'Model not found' : response.statusText;
            res.status(status).json({ error: message });
            return;
        }

        const data = await response.json();

        const report: any = {
            modelId: data.modelId,
            author: data.author,
            downloads: data.downloads,
            likes: data.likes,
            library: data.library_name || 'Unknown',
            license: data.cardData?.license || 'Unknown',
            lastModified: data.lastModified,
            files: { total: 0, risky: [], code: [], safe: [], unknown: [] },
            datasets: data.cardData?.datasets || [],
            securityIssues: [],
            scores: { fileRisk: 0, licenseRisk: 0, vulnerabilityScore: 0, overallScore: 0 },
            severity: 'Low'
        };

        if (data.siblings) {
            report.files.total = data.siblings.length;
            data.siblings.forEach((file: any) => {
                const filename = file.rfilename.toLowerCase();
                const risky = RISKY_EXTENSIONS.some(ext => filename.endsWith(ext));
                const code = CODE_EXTENSIONS.some(ext => filename.endsWith(ext));
                const safe = SAFE_EXTENSIONS.some(ext => filename.endsWith(ext));

                if (risky) {
                    report.files.risky.push(filename);
                    report.securityIssues.push({ level: 'Critical', type: 'Unsafe Serialization', message: `Risk: ${filename}` });
                } else if (code) {
                    report.files.code.push(filename);
                    report.securityIssues.push({ level: 'Medium', type: 'Code Execution', message: `Code: ${filename}` });
                } else if (safe) {
                    report.files.safe.push(filename);
                } else {
                    report.files.unknown.push(filename);
                }
            });
        }

        const tags: string[] = data.tags || [];
        if (tags.some(tag => SENSITIVE_DOMAINS.some(domain => tag.includes(domain)))) {
            report.securityIssues.push({
                level: 'Info',
                type: 'Sensitive Domain',
                message: 'Possible privacy concerns'
            });
        }

        const knownOpenLicenses = ['mit', 'apache-2.0', 'openrail'];
        const lower = report.license.toLowerCase();
        if (['unknown', 'other'].includes(lower)) report.scores.licenseRisk = 7;
        else if (knownOpenLicenses.some(l => lower.includes(l))) report.scores.licenseRisk = 0;
        else report.scores.licenseRisk = 4;

        if (report.files.risky.length > 0) report.scores.fileRisk = 10;
        else if (report.files.code.length > 0) report.scores.fileRisk = 5;
        else report.scores.fileRisk = 1;

        const combined = (data.cardData?.text || '').toLowerCase() + ' ' + tags.join(' ').toLowerCase();
        let red = 0;
        const found: string[] = [];
        REDTEAM_KEYWORDS.forEach(k => {
            if (combined.includes(k)) {
                found.push(k);
                red += 15;
            }
        });
        red = Math.min(100, red);

        report.redTeamInsights = {
            score: red,
            level: red >= 60 ? 'High' : red >= 30 ? 'Medium' : 'Low',
            findings: found.length ? found.slice(0, 3) : ['No red team flags']
        };

        const raw = (report.scores.fileRisk * 6) + (report.scores.licenseRisk * 2);
        report.scores.overallScore = Math.min(10, Math.ceil(raw / 8));
        if (report.scores.overallScore >= 8) report.severity = 'Critical';
        else if (report.scores.overallScore >= 5) report.severity = 'High';
        else if (report.scores.overallScore >= 3) report.severity = 'Medium';

        res.status(200).json(report);
    } catch (err: any) {
        res.status(500).json({ error: err.message || 'Internal error' });
    }
}
