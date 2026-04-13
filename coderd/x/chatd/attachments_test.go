package chatd //nolint:testpackage

import (
	"testing"
	"time"

	"charm.land/fantasy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/x/chatd/chatloop"
	"github.com/coder/coder/v2/coderd/x/chatd/chattool"
	"github.com/coder/coder/v2/codersdk"
)

func TestBuildAssistantPartsForPersist_PromotesToolAttachments(t *testing.T) {
	t.Parallel()

	fileID := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	response := chattool.WithAttachments(
		fantasy.NewTextResponse(`{"ok":true}`),
		chattool.AttachmentMetadata{
			FileID:    fileID,
			MediaType: "image/png",
			Name:      "screenshot.png",
		},
	)
	toolCallAt := time.Date(2026, time.April, 10, 0, 0, 0, 0, time.UTC)

	parts, err := buildAssistantPartsForPersist(
		[]fantasy.Content{fantasy.TextContent{Text: "Here is the screenshot."}},
		[]fantasy.ToolResultContent{{
			ToolCallID:       "call-1",
			ToolName:         "computer",
			ClientMetadata:   response.Metadata,
			ProviderExecuted: false,
		}},
		chatloop.PersistedStep{
			ToolCallCreatedAt: map[string]time.Time{
				"call-1": toolCallAt,
			},
		},
		nil,
	)
	require.NoError(t, err)

	require.Len(t, parts, 2)
	require.Equal(t, codersdk.ChatMessagePartTypeText, parts[0].Type)
	require.Equal(t, "Here is the screenshot.", parts[0].Text)
	require.Equal(t, codersdk.ChatMessagePartTypeFile, parts[1].Type)
	require.True(t, parts[1].FileID.Valid)
	require.Equal(t, fileID, parts[1].FileID.UUID)
	require.Equal(t, "image/png", parts[1].MediaType)
	require.Equal(t, "screenshot.png", parts[1].Name)
}

func TestBuildAssistantPartsForPersist_OnlyAttachments(t *testing.T) {
	t.Parallel()

	fileID := uuid.MustParse("bbbbbbbb-cccc-dddd-eeee-ffffffffffff")
	response := chattool.WithAttachments(
		fantasy.NewTextResponse(`{"ok":true}`),
		chattool.AttachmentMetadata{
			FileID:    fileID,
			MediaType: "text/plain",
			Name:      "build.log",
		},
	)

	parts, err := buildAssistantPartsForPersist(
		nil,
		[]fantasy.ToolResultContent{{ClientMetadata: response.Metadata}},
		chatloop.PersistedStep{},
		nil,
	)
	require.NoError(t, err)

	require.Len(t, parts, 1)
	require.Equal(t, codersdk.ChatMessagePartTypeFile, parts[0].Type)
	require.Equal(t, fileID, parts[0].FileID.UUID)
	require.Equal(t, "build.log", parts[0].Name)
}

func TestBuildAssistantPartsForPersist_InvalidAttachmentMetadataFails(t *testing.T) {
	t.Parallel()

	_, err := buildAssistantPartsForPersist(
		nil,
		[]fantasy.ToolResultContent{{
			ToolCallID:     "call-1",
			ToolName:       "attach_file",
			ClientMetadata: `{"attachments":[{"file_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}]}`,
		}},
		chatloop.PersistedStep{},
		nil,
	)
	require.ErrorContains(t, err, "missing media_type")
}
