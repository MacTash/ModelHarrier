/**
 * Known Vulnerable and Risky Base Models Database
 * 
 * This tracks models that have known security issues, jailbreaks,
 * or are commonly used as bases for uncensored fine-tunes.
 */

export interface VulnerableModel {
    pattern: RegExp;
    name: string;
    risk: 'critical' | 'high' | 'medium' | 'low';
    reason: string;
    cve?: string;
}

// Models known to have jailbreaks or safety bypasses
export const KNOWN_VULNERABLE_MODELS: VulnerableModel[] = [
    // Uncensored model families
    {
        pattern: /dolphin/i,
        name: 'Dolphin (Cognitive Computations)',
        risk: 'high',
        reason: 'Explicitly trained to remove refusals and safety guardrails'
    },
    {
        pattern: /wizard.?(uncensored|unfiltered)/i,
        name: 'WizardLM Uncensored',
        risk: 'high',
        reason: 'Fine-tuned to bypass safety training'
    },
    {
        pattern: /nous.?hermes.?(uncensored)?/i,
        name: 'Nous Hermes',
        risk: 'medium',
        reason: 'Known for reduced content restrictions'
    },
    {
        pattern: /openhermes/i,
        name: 'OpenHermes',
        risk: 'medium',
        reason: 'Synthetic data training may include unsafe content'
    },
    {
        pattern: /airoboros/i,
        name: 'Airoboros',
        risk: 'medium',
        reason: 'Trained with "jailbreak" style prompts'
    },
    {
        pattern: /goliath/i,
        name: 'Goliath Merged Models',
        risk: 'medium',
        reason: 'Model merges may inherit vulnerabilities from multiple sources'
    },

    // Models with known exploits
    {
        pattern: /gpt4all/i,
        name: 'GPT4All',
        risk: 'low',
        reason: 'Early open model with limited safety training'
    },
    {
        pattern: /llama.?2.?(7b|13b|70b).?chat/i,
        name: 'Llama 2 Chat',
        risk: 'low',
        reason: 'Published jailbreak techniques exist (DAN, Developer Mode)'
    },

    // Explicitly marked unsafe
    {
        pattern: /uncensored/i,
        name: 'Uncensored Model',
        risk: 'critical',
        reason: 'Model explicitly marketed as uncensored'
    },
    {
        pattern: /unfiltered/i,
        name: 'Unfiltered Model',
        risk: 'critical',
        reason: 'Model explicitly marketed as unfiltered'
    },
    {
        pattern: /no.?refusal/i,
        name: 'No-Refusal Model',
        risk: 'critical',
        reason: 'Trained to never refuse requests'
    },
    {
        pattern: /abliterated/i,
        name: 'Abliterated Model',
        risk: 'critical',
        reason: 'Safety features surgically removed via activation editing'
    },
];

// Risky base model patterns (not necessarily vulnerable, but warrant attention)
export const RISKY_BASE_MODELS: VulnerableModel[] = [
    {
        pattern: /mistral.?(7b|instruct)/i,
        name: 'Mistral',
        risk: 'low',
        reason: 'Limited safety training compared to competitors'
    },
    {
        pattern: /mixtral/i,
        name: 'Mixtral MoE',
        risk: 'low',
        reason: 'MoE architecture may have inconsistent safety across experts'
    },
    {
        pattern: /qwen/i,
        name: 'Qwen (Alibaba)',
        risk: 'low',
        reason: 'Different safety alignment methodology'
    },
    {
        pattern: /yi.?(6b|34b)/i,
        name: 'Yi (01.AI)',
        risk: 'low',
        reason: 'Limited public safety evaluation'
    },
    {
        pattern: /deepseek/i,
        name: 'DeepSeek',
        risk: 'low',
        reason: 'Code-focused training may bypass content filters'
    },
];

// Unsafe training data indicators
export const UNSAFE_DATASET_PATTERNS = [
    { pattern: /4chan/i, risk: 'high', reason: 'Known toxic content source' },
    { pattern: /reddit.?uncensored/i, risk: 'high', reason: 'Unmoderated content' },
    { pattern: /gab/i, risk: 'high', reason: 'Known for extremist content' },
    { pattern: /voat/i, risk: 'high', reason: 'Known for extremist content' },
    { pattern: /parler/i, risk: 'medium', reason: 'Limited moderation' },
    { pattern: /darkweb/i, risk: 'critical', reason: 'Potentially illegal content' },
    { pattern: /piracy/i, risk: 'medium', reason: 'Copyright concerns' },
];

// Keywords that indicate potential safety issues
export const UNSAFE_MODEL_KEYWORDS = [
    'uncensored',
    'unfiltered',
    'unrestricted',
    'no refusal',
    'no ethics',
    'no limits',
    'jailbreak',
    'jailbroken',
    'abliterated',
    'do anything',
    'bypass',
    'unrestricted',
    'no guardrails',
    'no safety',
    'harmful',
    'toxic',
    'NSFW',
    'adult only',
    '18+',
    'explicit',
];

// Positive safety indicators
export const SAFETY_INDICATORS = [
    'RLHF',
    'Constitutional AI',
    'safety trained',
    'aligned',
    'moderated',
    'filtered',
    'safe',
    'responsible',
    'ethical',
    'harmless',
    'helpful',
    'honest',
];

/**
 * Check a model ID against known vulnerable models
 */
export function checkVulnerableModel(modelId: string): VulnerableModel | null {
    const combined = [...KNOWN_VULNERABLE_MODELS, ...RISKY_BASE_MODELS];
    for (const model of combined) {
        if (model.pattern.test(modelId)) {
            return model;
        }
    }
    return null;
}

/**
 * Scan text for unsafe keywords
 */
export function findUnsafeKeywords(text: string): string[] {
    const lowerText = text.toLowerCase();
    return UNSAFE_MODEL_KEYWORDS.filter(kw => lowerText.includes(kw.toLowerCase()));
}

/**
 * Scan text for safety indicators
 */
export function findSafetyIndicators(text: string): string[] {
    const lowerText = text.toLowerCase();
    return SAFETY_INDICATORS.filter(ind => lowerText.includes(ind.toLowerCase()));
}
