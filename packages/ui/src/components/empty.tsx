import { slotElement } from "@openaudit/ui/lib/slot";
import { cn } from "@openaudit/ui/lib/utils";
import { cva, type VariantProps } from "class-variance-authority";

const Empty = slotElement(
	"div",
	"empty",
	"flex w-full min-w-0 flex-1 flex-col items-center justify-center gap-4 text-balance rounded-none border-dashed p-6 text-center md:p-12",
);

const EmptyHeader = slotElement(
	"div",
	"empty-header",
	"flex max-w-sm flex-col items-center gap-2",
);

const emptyMediaVariants = cva(
	"mb-2 flex shrink-0 items-center justify-center [&_svg]:pointer-events-none [&_svg]:shrink-0",
	{
		variants: {
			variant: {
				default: "bg-transparent",
				icon: "flex size-10 shrink-0 items-center justify-center rounded-none bg-muted text-foreground [&_svg:not([class*='size-'])]:size-5",
			},
		},
		defaultVariants: {
			variant: "default",
		},
	},
);

function EmptyMedia({
	className,
	variant = "default",
	...props
}: React.ComponentProps<"div"> & VariantProps<typeof emptyMediaVariants>) {
	return (
		<div
			data-slot="empty-icon"
			data-variant={variant}
			className={cn(emptyMediaVariants({ variant, className }))}
			{...props}
		/>
	);
}

const EmptyTitle = slotElement(
	"div",
	"empty-title",
	"cn-font-heading font-medium text-sm tracking-tight",
);

function EmptyDescription({ className, ...props }: React.ComponentProps<"p">) {
	return (
		<div
			data-slot="empty-description"
			className={cn(
				"text-muted-foreground text-sm/relaxed [&>a:hover]:text-primary [&>a]:underline [&>a]:underline-offset-4",
				className,
			)}
			{...props}
		/>
	);
}

const EmptyContent = slotElement(
	"div",
	"empty-content",
	"flex w-full min-w-0 max-w-sm flex-col items-center gap-4 text-balance text-sm",
);

export {
	Empty,
	EmptyContent,
	EmptyDescription,
	EmptyHeader,
	EmptyMedia,
	EmptyTitle,
};
