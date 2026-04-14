import {
	type ComponentProps,
	createContext,
	type FC,
	type HTMLProps,
	type ReactNode,
	useContext,
} from "react";
import { AlphaBadge, DeprecatedBadge } from "#/components/Badges/Badges";
import { Stack } from "#/components/Stack/Stack";
import { cn } from "#/utils/cn";

type FormContextValue = { direction?: "horizontal" | "vertical" };

const FormContext = createContext<FormContextValue>({
	direction: "horizontal",
});

type FormProps = HTMLProps<HTMLFormElement> & {
	direction?: FormContextValue["direction"];
};

export const Form: FC<FormProps> = ({
	className,
	children,
	direction,
	...formProps
}) => {
	return (
		<FormContext.Provider value={{ direction }}>
			<form
				className={cn(
					"flex flex-col gap-16",
					direction === "horizontal" ? "lg:gap-20" : "lg:gap-10",
					className,
				)}
				{...formProps}
			>
				{children}
			</form>
		</FormContext.Provider>
	);
};

export const HorizontalForm: FC<HTMLProps<HTMLFormElement>> = ({
	children,
	...formProps
}) => {
	return (
		<Form direction="horizontal" {...formProps}>
			{children}
		</Form>
	);
};

export const VerticalForm: FC<HTMLProps<HTMLFormElement>> = ({
	children,
	...formProps
}) => {
	return (
		<Form direction="vertical" {...formProps}>
			{children}
		</Form>
	);
};

interface FormSectionProps {
	children?: ReactNode;
	title: ReactNode;
	description: ReactNode;
	classes?: {
		root?: string;
		sectionInfo?: string;
		infoTitle?: string;
	};
	alpha?: boolean;
	deprecated?: boolean;
	ref?: React.Ref<HTMLElement>;
}

export const FormSection: FC<FormSectionProps> = ({
	children,
	title,
	description,
	classes = {},
	alpha = false,
	deprecated = false,
	ref,
}) => {
	const { direction } = useContext(FormContext);

	return (
		<section
			ref={ref}
			className={cn(
				"flex items-start flex-col gap-4 lg:gap-6",
				direction === "horizontal" && "lg:flex-row lg:gap-[120px]",
				classes.root,
			)}
		>
			<div
				className={cn(
					"w-full shrink-0 top-6",
					direction === "horizontal" && "max-w-[312px] lg:sticky",
					classes.sectionInfo,
				)}
			>
				<header className="flex items-center gap-4">
					<h2
						className={cn(
							"text-[20px] text-content-primary font-medium m-0 mb-2 flex flex-row items-center gap-3",
							classes.infoTitle,
						)}
					>
						{title}
					</h2>
					{alpha && <AlphaBadge />}
					{deprecated && <DeprecatedBadge />}
				</header>
				<div className="text-[14px] text-content-secondary leading-[160%] m-0">
					{description}
				</div>
			</div>

			{children}
		</section>
	);
};

export const FormFields: FC<ComponentProps<typeof Stack>> = (props) => {
	return (
		<Stack
			direction="column"
			spacing={3}
			{...props}
			className={cn("w-full", props.className)}
		/>
	);
};

export const FormFooter: FC<HTMLProps<HTMLDivElement>> = ({
	className,
	...props
}) => (
	<footer
		className={cn("flex items-center justify-end space-x-2 mt-2", className)}
		{...props}
	/>
);
