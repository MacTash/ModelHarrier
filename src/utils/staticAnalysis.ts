/**
 * Static Analysis Utilities
 * 
 * Deep analysis of model metadata, README, config, and training data.
 */

import {
    checkVulnerableModel,
    findUnsafeKeywords,
    findSafetyIndicators,
    UNSAFE_DATASET_PATTERNS,
    VulnerableModel
} from '../data/knownVulnerableModels';

export interface StaticAnalysisResult {
    // Base model analysis
    baseModel: string | null;
    baseModelRisk: VulnerableModel | null;

    // Content analysis
    unsafeKeywords: string[];
    safetyIndicators: string[];

    // Training data analysis
    trainingDataSources: string[];
    riskyDatasetFlags: Array<{ source: string; risk: string; reason: string }>;

    // Architecture concerns
    configFlags: string[];
    architectureType: string | null;

    // Spaces (free inference)
    spacesUrl: string | null;
    hasSpaces: boolean;

    // Aggregate score
    staticRiskScore: number;
    staticRiskLevel: 'critical' | 'high' | 'medium' | 'low';
    findings: string[];
}

/**
 * Extract base model from model card or config
 */
export function extractBaseModel(cardData: any, tags: string[]): string | null {
    // Check cardData for base_model field
    if (cardData?.base_model) {
        return cardData.base_model;
    }

    // Check tags for base_model: prefix
    const baseModelTag = tags.find(t => t.startsWith('base_model:'));
    if (baseModelTag) {
        return baseModelTag.replace('base_model:', '');
    }

    // Check model_type or architecture tags
    const modelTypeTags = ['llama', 'mistral', 'gpt2', 'bert', 'falcon', 'mpt', 'qwen', 'phi'];
    for (const tag of tags) {
        const lowerTag = tag.toLowerCase();
        for (const type of modelTypeTags) {
            if (lowerTag.includes(type)) {
                return tag;
            }
        }
    }

    return null;
}

/**
 * Extract training data sources from model card
 */
export function extractTrainingData(cardData: any, readmeContent?: string): string[] {
    const sources: Set<string> = new Set();

    // From cardData.datasets
    if (cardData?.datasets && Array.isArray(cardData.datasets)) {
        cardData.datasets.forEach((d: string) => sources.add(d));
    }

    // Parse README for dataset mentions
    if (readmeContent) {
        // Common dataset patterns
        const datasetPatterns = [
            /(?:trained|fine-?tuned|using)\s+(?:on\s+)?(?:the\s+)?([A-Za-z0-9_-]+(?:\s+dataset)?)/gi,
            /datasets?:\s*\[?([^\]\n]+)/gi,
            /huggingface\.co\/datasets\/([A-Za-z0-9_/-]+)/gi
        ];

        for (const pattern of datasetPatterns) {
            const matches = readmeContent.matchAll(pattern);
            for (const match of matches) {
                if (match[1]) {
                    sources.add(match[1].trim());
                }
            }
        }
    }

    return Array.from(sources);
}

/**
 * Analyze config.json for security concerns
 */
export function analyzeConfig(config: any): { flags: string[]; architecture: string | null } {
    const flags: string[] = [];
    let architecture: string | null = null;

    if (!config) {
        return { flags: ['No config.json found'], architecture: null };
    }

    // Get architecture type
    architecture = config.model_type || config.architectures?.[0] || null;

    // Check for concerning configurations
    if (config.torch_dtype === 'float16' || config.torch_dtype === 'bfloat16') {
        // This is actually normal, not flagging
    }

    // Check vocab size (unusually large might indicate custom tokens)
    if (config.vocab_size > 100000) {
        flags.push(`Large vocabulary size (${config.vocab_size}) - may have custom tokens`);
    }

    // Check for hidden/custom layers
    if (config.num_hidden_layers && config.num_hidden_layers > 80) {
        flags.push(`Very deep model (${config.num_hidden_layers} layers) - expensive to audit`);
    }

    // Check for custom architectures
    if (config.auto_map) {
        flags.push('Custom model code (auto_map) - requires code review');
    }

    // Check for trust_remote_code requirement
    if (config.trust_remote_code === true) {
        flags.push('CRITICAL: Requires trust_remote_code=True - arbitrary code execution risk');
    }

    return { flags, architecture };
}

/**
 * Analyze README/model card for security indicators
 */
export function analyzeReadme(readmeContent: string): {
    unsafePatterns: string[];
    safetyMentions: string[];
    concerningPhrases: string[];
} {
    const unsafePatterns = findUnsafeKeywords(readmeContent);
    const safetyMentions = findSafetyIndicators(readmeContent);
    const concerningPhrases: string[] = [];

    // Look for concerning phrases
    const concernPatterns = [
        /no\s+safety\s+filter/i,
        /removed?\s+(?:safety|refusal)/i,
        /bypass(?:es|ing)?\s+(?:safety|content)/i,
        /not\s+(?:safe|aligned)/i,
        /use\s+at\s+your\s+own\s+risk/i,
        /for\s+research\s+(?:only|purposes)/i,
        /not\s+for\s+production/i,
        /adult\s+content/i,
        /nsfw/i,
        /explicit/i,
    ];

    for (const pattern of concernPatterns) {
        const match = readmeContent.match(pattern);
        if (match) {
            concerningPhrases.push(match[0]);
        }
    }

    return { unsafePatterns, safetyMentions, concerningPhrases };
}

/**
 * Check training datasets for known risky sources
 */
export function analyzeDatasets(datasets: string[]): Array<{ source: string; risk: string; reason: string }> {
    const flags: Array<{ source: string; risk: string; reason: string }> = [];

    for (const dataset of datasets) {
        for (const pattern of UNSAFE_DATASET_PATTERNS) {
            if (pattern.pattern.test(dataset)) {
                flags.push({
                    source: dataset,
                    risk: pattern.risk,
                    reason: pattern.reason
                });
                break;
            }
        }
    }

    return flags;
}

/**
 * Calculate aggregate static risk score (0-100)
 */
export function calculateStaticRiskScore(analysis: Partial<StaticAnalysisResult>): {
    score: number;
    level: 'critical' | 'high' | 'medium' | 'low'
} {
    let score = 0;

    // Base model risk
    if (analysis.baseModelRisk) {
        switch (analysis.baseModelRisk.risk) {
            case 'critical': score += 40; break;
            case 'high': score += 30; break;
            case 'medium': score += 20; break;
            case 'low': score += 10; break;
        }
    }

    // Unsafe keywords
    score += Math.min(30, (analysis.unsafeKeywords?.length || 0) * 10);

    // Risky datasets
    for (const flag of analysis.riskyDatasetFlags || []) {
        switch (flag.risk) {
            case 'critical': score += 15; break;
            case 'high': score += 10; break;
            case 'medium': score += 5; break;
        }
    }

    // Config flags
    const criticalConfigFlags = (analysis.configFlags || []).filter(f =>
        f.includes('CRITICAL') || f.includes('trust_remote_code')
    );
    score += criticalConfigFlags.length * 25;
    score += ((analysis.configFlags?.length || 0) - criticalConfigFlags.length) * 5;

    // Reduce score for safety indicators
    score -= Math.min(20, (analysis.safetyIndicators?.length || 0) * 5);

    // Clamp to 0-100
    score = Math.max(0, Math.min(100, score));

    // Determine level
    let level: 'critical' | 'high' | 'medium' | 'low';
    if (score >= 70) level = 'critical';
    else if (score >= 50) level = 'high';
    else if (score >= 25) level = 'medium';
    else level = 'low';

    return { score, level };
}

/**
 * Full static analysis pipeline
 */
export function performStaticAnalysis(
    modelId: string,
    cardData: any,
    tags: string[],
    config?: any,
    readmeContent?: string,
    spacesUrl?: string | null
): StaticAnalysisResult {
    const findings: string[] = [];

    // Base model analysis
    const baseModel = extractBaseModel(cardData, tags);
    const baseModelRisk = baseModel ? checkVulnerableModel(baseModel) : checkVulnerableModel(modelId);

    if (baseModelRisk) {
        findings.push(`Base model risk: ${baseModelRisk.name} - ${baseModelRisk.reason}`);
    }

    // Training data
    const trainingDataSources = extractTrainingData(cardData, readmeContent);
    const riskyDatasetFlags = analyzeDatasets(trainingDataSources);

    for (const flag of riskyDatasetFlags) {
        findings.push(`Risky dataset: ${flag.source} - ${flag.reason}`);
    }

    // Config analysis
    const { flags: configFlags, architecture: architectureType } = analyzeConfig(config);

    for (const flag of configFlags) {
        findings.push(flag);
    }

    // README analysis
    const readmeAnalysis = readmeContent
        ? analyzeReadme(readmeContent)
        : { unsafePatterns: [], safetyMentions: [], concerningPhrases: [] };

    const unsafeKeywords = [
        ...findUnsafeKeywords(modelId),
        ...readmeAnalysis.unsafePatterns,
        ...readmeAnalysis.concerningPhrases
    ];

    if (unsafeKeywords.length > 0) {
        findings.push(`Unsafe patterns detected: ${unsafeKeywords.join(', ')}`);
    }

    const safetyIndicators = readmeAnalysis.safetyMentions;

    // Calculate score
    const partialResult = {
        baseModelRisk,
        unsafeKeywords,
        safetyIndicators,
        riskyDatasetFlags,
        configFlags
    };

    const { score: staticRiskScore, level: staticRiskLevel } = calculateStaticRiskScore(partialResult);

    return {
        baseModel,
        baseModelRisk,
        unsafeKeywords: [...new Set(unsafeKeywords)],
        safetyIndicators,
        trainingDataSources,
        riskyDatasetFlags,
        configFlags,
        architectureType,
        spacesUrl: spacesUrl || null,
        hasSpaces: !!spacesUrl,
        staticRiskScore,
        staticRiskLevel,
        findings
    };
}
