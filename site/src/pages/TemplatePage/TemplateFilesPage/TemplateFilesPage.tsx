import type { FC } from "react";
import { useQuery } from "react-query";
import { useParams } from "react-router";
import {
	previousTemplateVersion,
	templateFiles,
} from "#/api/queries/templates";
import { Loader } from "#/components/Loader/Loader";
import { TemplateFiles } from "#/modules/templates/TemplateFiles/TemplateFiles";
import { useTemplateLayoutContext } from "#/pages/TemplatePage/TemplateLayout";
import { getTemplatePageTitle } from "../utils";

const TemplateFilesPage: FC = () => {
	const { organization: organizationName = "default" } = useParams() as {
		organization?: string;
	};
	const { template, activeVersion } = useTemplateLayoutContext();
	// activeVersion.job and previousVersion.job are typed as always
	// present but the runtime can still see a version whose job has
	// not been populated yet (a provisioner import that has not
	// reached convertProvisionerJob, a 200 with a partial body from a
	// misbehaving reverse proxy, etc.). Guard the .job access so the
	// page degrades to a Loader instead of crashing the React tree.
	const currentFileID = activeVersion.job?.file_id ?? "";
	const { data: currentFiles } = useQuery({
		...templateFiles(currentFileID),
		enabled: currentFileID !== "",
	});
	const previousVersionQuery = useQuery(
		previousTemplateVersion(
			organizationName,
			template.name,
			activeVersion.name,
		),
	);
	const previousVersion = previousVersionQuery.data;
	const previousFileID = previousVersion?.job?.file_id ?? "";
	const hasPreviousVersion =
		previousVersionQuery.isSuccess &&
		previousVersion !== null &&
		previousFileID !== "";
	const { data: previousFiles } = useQuery({
		...templateFiles(previousFileID),
		enabled: hasPreviousVersion,
	});
	const shouldDisplayFiles =
		currentFiles && (!hasPreviousVersion || previousFiles);

	return (
		<>
			<title>{getTemplatePageTitle("Source Code", template)}</title>

			{shouldDisplayFiles ? (
				<TemplateFiles
					organizationName={template.organization_name}
					templateName={template.name}
					versionName={activeVersion.name}
					currentFiles={currentFiles}
					baseFiles={previousFiles}
				/>
			) : (
				<Loader />
			)}
		</>
	);
};

export default TemplateFilesPage;
