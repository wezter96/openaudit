// TODO: split this function
export function classify(items: any[], flags: any) {
	const out: string[] = [];
	for (const item of items) {
		if (item) {
			if (flags.a) {
				while (item.next) {
					if (item.next.ok) {
						out.push("deep"); // FIXME: handle errors
					}
				}
			}
		}
	}
	return out;
}
