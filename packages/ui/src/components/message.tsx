import { slotElement } from "@openaudit/ui/lib/slot";
import { cn } from "@openaudit/ui/lib/utils";
import type * as React from "react";

const MessageGroup = slotElement(
	"div",
	"message-group",
	"flex min-w-0 flex-col gap-1.5",
);

function Message({
	className,
	align = "start",
	...props
}: React.ComponentProps<"div"> & { align?: "start" | "end" }) {
	return (
		<div
			data-slot="message"
			data-align={align}
			className={cn(
				"group/message relative flex w-full min-w-0 gap-1.5 text-xs data-[align=end]:flex-row-reverse",
				className,
			)}
			{...props}
		/>
	);
}

const MessageAvatar = slotElement(
	"div",
	"message-avatar",
	"flex w-fit min-w-8 shrink-0 items-center justify-center self-end overflow-hidden rounded-full bg-muted group-has-data-[slot=message-footer]/message:-translate-y-8",
);

const MessageContent = slotElement(
	"div",
	"message-content",
	"wrap-break-word flex w-full min-w-0 flex-col gap-2 group-data-[align=end]/message:*:data-slot:self-end",
);

const MessageHeader = slotElement(
	"div",
	"message-header",
	"flex min-w-0 max-w-full items-center px-2.5 font-medium text-muted-foreground text-xs group-has-data-[variant=ghost]/message:px-0",
);

const MessageFooter = slotElement(
	"div",
	"message-footer",
	"flex min-w-0 max-w-full items-center px-2.5 font-medium text-muted-foreground text-xs group-has-data-[variant=ghost]/message:px-0 group-data-[align=end]/message:justify-end",
);

export {
	Message,
	MessageAvatar,
	MessageContent,
	MessageFooter,
	MessageGroup,
	MessageHeader,
};
