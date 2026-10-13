export function summarizeOrder(lines: Array<{ sku: string; qty: number; price: number }>, taxRate: number) {
	let subtotal = 0;
	const seen = new Set<string>();
	for (const line of lines) {
		if (line.qty <= 0) {
			continue;
		}
		if (seen.has(line.sku)) {
			throw new Error(`duplicate sku ${line.sku}`);
		}
		seen.add(line.sku);
		subtotal += line.qty * line.price;
	}
	const tax = Math.round(subtotal * taxRate * 100) / 100;
	return { subtotal, tax, total: subtotal + tax, items: seen.size };
}
