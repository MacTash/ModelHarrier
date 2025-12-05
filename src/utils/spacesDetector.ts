/**
 * HuggingFace Spaces Detector
 * 
 * Detects if a model has associated Spaces (Gradio/Streamlit demos)
 * that can be used for manual red team testing without API keys.
 */

export interface SpacesInfo {
    hasSpaces: boolean;
    spacesUrl: string | null;
    spaceType: 'gradio' | 'streamlit' | 'static' | 'docker' | 'unknown' | null;
    spaceName: string | null;
}

/**
 * Check if model has associated Spaces
 * This checks if there's a Space with the same namespace/name pattern
 */
export async function detectSpaces(modelId: string): Promise<SpacesInfo> {
    // Default response
    const noSpaces: SpacesInfo = {
        hasSpaces: false,
        spacesUrl: null,
        spaceType: null,
        spaceName: null
    };

    try {
        // Try to fetch Space info with same ID
        const spaceResponse = await fetch(
            `https://huggingface.co/api/spaces/${encodeURIComponent(modelId)}`
        );

        if (spaceResponse.ok) {
            const spaceData = await spaceResponse.json();
            return {
                hasSpaces: true,
                spacesUrl: `https://huggingface.co/spaces/${modelId}`,
                spaceType: detectSpaceType(spaceData),
                spaceName: modelId
            };
        }

        // If exact match fails, check author's spaces
        const author = modelId.split('/')[0];
        if (author) {
            const authorSpacesResponse = await fetch(
                `https://huggingface.co/api/spaces?author=${encodeURIComponent(author)}&limit=20`
            );

            if (authorSpacesResponse.ok) {
                const spaces = await authorSpacesResponse.json();

                // Look for a space that might be related to this model
                const modelName = modelId.split('/')[1]?.toLowerCase() || '';
                const relatedSpace = spaces.find((space: any) => {
                    const spaceName = space.id?.toLowerCase() || '';
                    return spaceName.includes(modelName) ||
                        modelName.includes(spaceName.split('/')[1] || '');
                });

                if (relatedSpace) {
                    return {
                        hasSpaces: true,
                        spacesUrl: `https://huggingface.co/spaces/${relatedSpace.id}`,
                        spaceType: detectSpaceType(relatedSpace),
                        spaceName: relatedSpace.id
                    };
                }
            }
        }

        return noSpaces;
    } catch (error) {
        console.error('Spaces detection error:', error);
        return noSpaces;
    }
}

/**
 * Detect the type of Space from API response
 */
function detectSpaceType(spaceData: any): SpacesInfo['spaceType'] {
    const sdk = spaceData.sdk?.toLowerCase();

    if (sdk === 'gradio') return 'gradio';
    if (sdk === 'streamlit') return 'streamlit';
    if (sdk === 'static') return 'static';
    if (sdk === 'docker') return 'docker';

    return 'unknown';
}

/**
 * Get direct embed URL for Space (if Gradio)
 */
export function getSpaceEmbedUrl(spacesUrl: string): string | null {
    if (!spacesUrl) return null;

    // Convert HF space URL to embed URL
    // https://huggingface.co/spaces/author/name -> https://author-name.hf.space
    const match = spacesUrl.match(/huggingface\.co\/spaces\/([^/]+)\/([^/]+)/);
    if (match) {
        const [, author, name] = match;
        return `https://${author}-${name}.hf.space`;
    }

    return null;
}

/**
 * Check if Space is likely to be a chat/text interface (suitable for red teaming)
 */
export function isTextInterface(spaceData: any): boolean {
    const tags = spaceData.tags || [];
    const cardData = spaceData.cardData || {};

    const textIndicators = [
        'chat',
        'text-generation',
        'conversational',
        'chatbot',
        'llm',
        'language-model',
        'text2text-generation'
    ];

    // Check tags
    for (const tag of tags) {
        if (textIndicators.some(ind => tag.toLowerCase().includes(ind))) {
            return true;
        }
    }

    // Check pipeline tag
    const pipeline = cardData.pipeline_tag || spaceData.pipeline_tag;
    if (pipeline && textIndicators.some(ind => pipeline.toLowerCase().includes(ind))) {
        return true;
    }

    return false;
}

/**
 * Known popular model Spaces that are good for testing
 */
export const KNOWN_MODEL_SPACES: Record<string, string> = {
    // Meta LLaMA
    'meta-llama/Llama-2-7b-chat-hf': 'https://huggingface.co/spaces/huggingface-projects/llama-2-7b-chat',
    'meta-llama/Llama-2-13b-chat-hf': 'https://huggingface.co/spaces/huggingface-projects/llama-2-13b-chat',

    // Mistral
    'mistralai/Mistral-7B-Instruct-v0.1': 'https://huggingface.co/spaces/mistralai/Mistral-7B-Instruct-v0.1',
    'mistralai/Mixtral-8x7B-Instruct-v0.1': 'https://huggingface.co/spaces/mistralai/Mixtral-8x7B-Instruct-v0.1',

    // OpenChat
    'openchat/openchat_3.5': 'https://huggingface.co/spaces/openchat/openchat_3.5',

    // Nous Research
    'NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO': 'https://huggingface.co/spaces/NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO',
};

/**
 * Get known Space for a model if it exists
 */
export function getKnownSpace(modelId: string): string | null {
    return KNOWN_MODEL_SPACES[modelId] || null;
}
