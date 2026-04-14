import type { FC, ReactNode } from "react";
import { Avatar } from "#/components/Avatar/Avatar";

type AvatarCardProps = {
	header: string;
	imgUrl: string;
	subtitle?: ReactNode;
	maxWidth?: number | "none";
};

export const AvatarCard: FC<AvatarCardProps> = ({
	header,
	imgUrl,
	subtitle,
	maxWidth = "none",
}) => {
	return (
		<div
			className="flex flex-row flex-nowrap items-center border border-solid border-border gap-4 p-4 rounded-lg cursor-default"
			style={{
				maxWidth: maxWidth === "none" ? undefined : `${maxWidth}px`,
			}}
		>
			{/**
			 * minWidth is necessary to ensure that the text truncation works properly
			 * with flex containers that don't have fixed width
			 *
			 * @see {@link https://css-tricks.com/flexbox-truncated-text/}
			 */}
			<div className="mr-auto min-w-0">
				<h3
					// Lets users hover over truncated text to see whole thing
					title={header}
					className="text-[1rem] font-normal leading-[1.4] m-0 truncate"
				>
					{header}
				</h3>

				{subtitle && (
					<div className="text-[14px] leading-[160%] text-content-secondary">
						{subtitle}
					</div>
				)}
			</div>

			<Avatar size="lg" src={imgUrl} fallback={header} />
		</div>
	);
};
