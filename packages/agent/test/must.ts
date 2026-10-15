/** Returns `value`, failing the test with a clear message when it is missing. */
export const must = <T>(value: T | null | undefined, what: string): T => {
	if (value === undefined || value === null)
		throw new Error(`expected ${what}, got ${value}`);
	return value;
};
