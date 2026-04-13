package chatd

import (
	"charm.land/fantasy"
	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/x/chatd/chatloop"
	"github.com/coder/coder/v2/coderd/x/chatd/chatprompt"
	"github.com/coder/coder/v2/coderd/x/chatd/chattool"
	"github.com/coder/coder/v2/codersdk"
)

func buildAssistantPartsForPersist(
	assistantBlocks []fantasy.Content,
	toolResults []fantasy.ToolResultContent,
	step chatloop.PersistedStep,
	toolNameToConfigID map[string]uuid.UUID,
) ([]codersdk.ChatMessagePart, error) {
	parts := make([]codersdk.ChatMessagePart, 0, len(assistantBlocks)+len(toolResults))
	for _, block := range assistantBlocks {
		part := chatprompt.PartFromContent(block)
		if part.ToolName != "" {
			if configID, ok := toolNameToConfigID[part.ToolName]; ok {
				part.MCPServerConfigID = uuid.NullUUID{UUID: configID, Valid: true}
			}
		}
		if part.Type == codersdk.ChatMessagePartTypeToolCall && part.ToolCallID != "" && step.ToolCallCreatedAt != nil {
			if ts, ok := step.ToolCallCreatedAt[part.ToolCallID]; ok {
				part.CreatedAt = &ts
			}
		}
		if part.Type == codersdk.ChatMessagePartTypeToolResult && part.ToolCallID != "" && step.ToolResultCreatedAt != nil {
			if ts, ok := step.ToolResultCreatedAt[part.ToolCallID]; ok {
				part.CreatedAt = &ts
			}
		}
		parts = append(parts, part)
	}
	for _, tr := range toolResults {
		attachmentParts, err := chattool.AttachmentPartsFromMetadata(tr.ClientMetadata)
		if err != nil {
			return nil, xerrors.Errorf(
				"decode attachments for tool %q (%s): %w",
				tr.ToolName,
				tr.ToolCallID,
				err,
			)
		}
		parts = append(parts, attachmentParts...)
	}
	return parts, nil
}
