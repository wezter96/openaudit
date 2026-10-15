/** Reading request and response bodies without trusting their size. */

/** A body length in bytes. */
export type Bytes = number;

const concat = (chunks: ReadonlyArray<Uint8Array>) => {
	const out = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out;
};

export interface Read {
	/** At most `limit` bytes. */
	readonly bytes: Uint8Array<ArrayBuffer>;
	/** The stream had more than `limit` bytes; reading stopped there. */
	readonly over: boolean;
}

/** Reads a stream until it ends or passes `limit` bytes. */
export const readUpTo = async (
	stream: ReadableStream<Uint8Array> | null,
	limit: Bytes,
): Promise<Read> => {
	const reader = stream?.getReader();
	const chunks: Uint8Array[] = [];
	let size = 0;
	while (reader && size <= limit) {
		const { done, value } = await reader.read();
		if (done) return { bytes: concat(chunks), over: false };
		chunks.push(value);
		size += value.byteLength;
	}
	await reader?.cancel().catch(() => undefined);
	return { bytes: concat(chunks).subarray(0, limit), over: size > limit };
};
