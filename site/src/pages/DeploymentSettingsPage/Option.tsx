import { WrenchIcon } from "lucide-react";
import type { FC, HTMLAttributes, PropsWithChildren } from "react";
import { DisabledBadge, EnabledBadge } from "#/components/Badges/Badges";
import { cn } from "#/utils/cn";

export const OptionName: FC<PropsWithChildren> = ({ children }) => {
	return (
		<span className="block text-sm font-medium text-content-primary">
			{children}
		</span>
	);
};

export const OptionDescription: FC<PropsWithChildren> = ({ children }) => {
	return <span className="text-sm font-normal">{children}</span>;
};

interface OptionValueProps {
	children?: boolean | number | string | string[] | Record<string, boolean>;
}

export const OptionValue: FC<OptionValueProps> = (props) => {
	const { children: value } = props;

	if (typeof value === "boolean") {
		return (
			<div className="option-value-boolean">
				{value ? <EnabledBadge /> : <DisabledBadge />}
			</div>
		);
	}

	if (typeof value === "number") {
		return (
			<span className="option-value-number font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4">
				{value}
			</span>
		);
	}

	if (!value || value.length === 0) {
		return (
			<span className="option-value-empty font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4">
				Not set
			</span>
		);
	}

	if (typeof value === "string") {
		return (
			<span className="option-value-string font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4">
				{value}
			</span>
		);
	}

	if (typeof value === "object" && !Array.isArray(value)) {
		return (
			<ul className="option-array list-none">
				{Object.entries(value)
					.sort((a, b) => a[0].localeCompare(b[0]))
					.map(([option, isEnabled]) => (
						<li
							key={option}
							className={cn(
								"font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4",
								!isEnabled && "ml-8 text-content-disabled",
								`option-array-item-${option}`,
								isEnabled ? "option-enabled" : "option-disabled",
							)}
						>
							<div className="inline-flex items-center">
								{isEnabled && <WrenchIcon className="size-4 mx-2" />}
								{option}
							</div>
						</li>
					))}
			</ul>
		);
	}

	if (Array.isArray(value)) {
		return (
			<ul className="option-array list-inside">
				{value.map((item) => (
					<li
						key={item}
						className="font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4"
					>
						{item}
					</li>
				))}
			</ul>
		);
	}

	return (
		<span className="option-value-json font-mono text-[14px] [overflow-wrap:anywhere] select-all [&_ul]:p-4">
			{JSON.stringify(value)}
		</span>
	);
};

type OptionConfigProps = HTMLAttributes<HTMLDivElement> & { isSource: boolean };

// OptionConfig takes a isSource bool to indicate if the Option is the source of the configured value.
export const OptionConfig: FC<OptionConfigProps> = ({
	isSource,
	className,
	...attrs
}) => {
	return (
		<div
			{...attrs}
			className={cn(
				"font-mono text-[13px] font-semibold bg-surface-secondary inline-flex items-center rounded p-1.5 leading-none gap-1.5 border border-solid border-border",
				isSource &&
					"border-border-pending [&_.OptionConfigFlag]:bg-content-link text-content-primary",
				className,
			)}
		/>
	);
};

export const OptionConfigFlag: FC<HTMLAttributes<HTMLDivElement>> = ({
	className,
	...props
}) => {
	return (
		<div
			{...props}
			className={cn(
				"OptionConfigFlag text-[10px] font-semibold block bg-border leading-none px-1 py-0.5 rounded-[1px]",
				className,
			)}
		/>
	);
};
