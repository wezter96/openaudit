/**
 * Resource limits for decoding untrusted app artifacts. A crafted APK/IPA must
 * fail fast with a parse error instead of hanging or exhausting memory.
 */

/** Max elements/attributes/values materialised from one document. */
export const MAX_NODES = 200_000;
/** Max element/container nesting. */
export const MAX_DEPTH = 256;
/** Max length of a single decoded string or data blob, in bytes. */
export const MAX_VALUE_BYTES = 4 * 1024 * 1024;
/** Max total string bytes decoded from one document. */
export const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;

export class DecodeLimitError extends Error {}

/** Counts materialised nodes and decoded bytes; throws past the limits. */
export const makeBudget = (
	maxNodes = MAX_NODES,
	maxBytes = MAX_DOCUMENT_BYTES,
) => {
	let nodes = 0;
	let bytes = 0;
	return {
		get nodes() {
			return nodes;
		},
		/** Counts `n` materialised nodes (a shared subtree counts every time). */
		node: (n = 1) => {
			nodes += n;
			if (nodes > maxNodes)
				throw new DecodeLimitError(`Document exceeds ${maxNodes} nodes`);
		},
		bytes: (n: number) => {
			if (n > MAX_VALUE_BYTES)
				throw new DecodeLimitError(`Value exceeds ${MAX_VALUE_BYTES} bytes`);
			bytes += n;
			if (bytes > maxBytes)
				throw new DecodeLimitError(`Document exceeds ${maxBytes} bytes`);
		},
		depth: (d: number) => {
			if (d > MAX_DEPTH)
				throw new DecodeLimitError(`Nesting deeper than ${MAX_DEPTH}`);
		},
	};
};

export type Budget = ReturnType<typeof makeBudget>;
