import { cn } from "@openaudit/ui/lib/utils";
import type * as React from "react";
import { createElement } from "react";

/** A plain element that only carries a data-slot and its base classes. */
export function slotElement<T extends "div" | "span">(
	tag: T,
	slot: string,
	base: string,
) {
	return function SlotElement({
		className,
		...props
	}: React.ComponentProps<T>) {
		return createElement(tag, {
			"data-slot": slot,
			className: cn(base, className),
			...props,
		});
	};
}
