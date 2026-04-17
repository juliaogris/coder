package coderd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/coder/coder/v2/coderd/coderdtest"
	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/database/dbauthz"
	"github.com/coder/coder/v2/coderd/database/dbgen"
	"github.com/coder/coder/v2/coderd/rbac"
	"github.com/coder/coder/v2/coderd/rbac/policy"
	"github.com/coder/coder/v2/coderd/x/chatd/chatprompt"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/testutil"
)

func createSharedChat(
	ctx context.Context,
	t *testing.T,
	ownerClient *codersdk.ExperimentalClient,
	orgID uuid.UUID,
	title string,
) codersdk.Chat {
	t.Helper()

	chat, err := ownerClient.CreateChat(ctx, codersdk.CreateChatRequest{
		OrganizationID: orgID,
		Content: []codersdk.ChatInputPart{
			{
				Type: codersdk.ChatInputPartTypeText,
				Text: title,
			},
		},
	})
	require.NoError(t, err)
	return chat
}

func TestPatchChatACL_AddsUserAndGroup(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	group := dbgen.Group(t, db, database.Group{OrganizationID: firstUser.OrganizationID})
	dbgen.GroupMember(t, db, database.GroupMemberTable{GroupID: group.ID, UserID: viewer.ID})

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "acl patch add user+group")

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	acl, err := ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)

	require.Len(t, acl.Users, 1)
	require.Equal(t, viewer.ID, acl.Users[0].ID)
	require.Equal(t, codersdk.ChatRoleRead, acl.Users[0].Role)

	require.Len(t, acl.Groups, 1)
	require.Equal(t, group.ID, acl.Groups[0].ID)
	require.Equal(t, codersdk.ChatRoleRead, acl.Groups[0].Role)
}

func TestPatchChatACL_RejectsNonReadRole(t *testing.T) {
	t.Parallel()

	// Keep the reject cases and one happy-path so the test pins both
	// directions: anything that is not exactly "read" (canonical) or
	// "" (ChatRoleDeleted) must be refused. "deleted" is the spelled-
	// out word, not the empty sentinel, so it must also fail.
	cases := []struct {
		name   string
		role   codersdk.ChatRole
		reject bool
	}{
		{name: "admin", role: codersdk.ChatRole("admin"), reject: true},
		{name: "UppercaseREAD", role: codersdk.ChatRole("READ"), reject: true},
		{name: "write", role: codersdk.ChatRole("write"), reject: true},
		{name: "PaddedRead", role: codersdk.ChatRole(" read "), reject: true},
		{name: "SpelledDeleted", role: codersdk.ChatRole("deleted"), reject: true},
		{name: "owner", role: codersdk.ChatRole("owner"), reject: true},
		{name: "read", role: codersdk.ChatRoleRead, reject: false},
	}

	ownerClient := newChatClient(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.Context(t, testutil.WaitLong)
			chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID,
				"acl patch role case: "+tc.name)
			err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
				UserRoles: map[string]codersdk.ChatShareEntry{
					viewer.ID.String(): {Role: tc.role},
				},
			})
			if tc.reject {
				requireSDKError(t, err, http.StatusBadRequest)
				return
			}
			require.NoError(t, err, "%q must be accepted as a valid role", tc.role)
		})
	}
}

func TestPatchChatACL_SubChatRejected(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	parent := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "root chat for sub-chat patch")

	subChat, err := db.InsertChat(dbauthz.AsSystemRestricted(ctx), database.InsertChatParams{
		OrganizationID:    firstUser.OrganizationID,
		Status:            database.ChatStatusWaiting,
		ClientType:        database.ChatClientTypeUi,
		OwnerID:           firstUser.UserID,
		LastModelConfigID: modelConfig.ID,
		Title:             "sub-chat",
		ParentChatID:      uuid.NullUUID{UUID: parent.ID, Valid: true},
		RootChatID:        uuid.NullUUID{UUID: parent.ID, Valid: true},
	})
	require.NoError(t, err)

	err = ownerClient.UpdateChatACL(ctx, subChat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	sdkErr := requireSDKError(t, err, http.StatusBadRequest)
	require.Contains(t, sdkErr.Message, "root chats")
}

func TestPatchChatACL_StoresShareFlags(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	group := dbgen.Group(t, db, database.Group{OrganizationID: firstUser.OrganizationID})
	dbgen.GroupMember(t, db, database.GroupMemberTable{GroupID: group.ID, UserID: viewer.ID})

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "acl patch stores share flags")

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead, ShareToolCalls: true, ShareAttachments: false},
		},
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleRead, ShareToolCalls: false, ShareAttachments: true},
		},
	})
	require.NoError(t, err)

	acl, err := ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)

	require.Len(t, acl.Users, 1)
	require.Equal(t, viewer.ID, acl.Users[0].ID)
	require.True(t, acl.Users[0].ShareToolCalls)
	require.False(t, acl.Users[0].ShareAttachments)

	require.Len(t, acl.Groups, 1)
	require.Equal(t, group.ID, acl.Groups[0].ID)
	require.False(t, acl.Groups[0].ShareToolCalls)
	require.True(t, acl.Groups[0].ShareAttachments)
}

func TestPatchChatACL_DefaultsHideEverything(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient := newChatClient(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "acl patch default flags")

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	acl, err := ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)
	require.Len(t, acl.Users, 1)
	require.False(t, acl.Users[0].ShareToolCalls)
	require.False(t, acl.Users[0].ShareAttachments)
}

func TestDeleteChatACL_ClearsEntries(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient := newChatClient(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "delete clears entries")

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	err = ownerClient.DeleteChatACL(ctx, chat.ID)
	require.NoError(t, err)

	acl, err := ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)
	require.Empty(t, acl.Users)
	require.Empty(t, acl.Groups)
}

func TestListChats_SharedFilter(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient := newChatClient(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	ownedOnly := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "owned only")
	sharedChat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "owned and shared")

	err := ownerClient.UpdateChatACL(ctx, sharedChat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	defaultList, err := viewerClient.ListChats(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, defaultList, "default list should only include owned chats")

	includeList, err := viewerClient.ListChats(ctx, &codersdk.ListChatsOptions{
		Shared: codersdk.ChatSharedFilterInclude,
	})
	require.NoError(t, err)
	includeIDs := chatIDSet(includeList)
	require.Contains(t, includeIDs, sharedChat.ID)
	require.NotContains(t, includeIDs, ownedOnly.ID, "viewer does not own or share the first chat")

	onlyList, err := viewerClient.ListChats(ctx, &codersdk.ListChatsOptions{
		Shared: codersdk.ChatSharedFilterOnly,
	})
	require.NoError(t, err)
	onlyIDs := chatIDSet(onlyList)
	require.Contains(t, onlyIDs, sharedChat.ID)
	require.Len(t, onlyIDs, 1, "viewer has exactly one shared chat")

	ownerList, err := ownerClient.ListChats(ctx, nil)
	require.NoError(t, err)
	ownerIDs := chatIDSet(ownerList)
	require.Contains(t, ownerIDs, ownedOnly.ID)
	require.Contains(t, ownerIDs, sharedChat.ID)

	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats?shared=wat", nil)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusBadRequest, res.StatusCode)
}

// insertShareTestAssistantMessage inserts a single assistant message
// with every part type the filter treats specially, plus text and
// reasoning (which must always pass through).
func insertShareTestAssistantMessage(
	ctx context.Context,
	t *testing.T,
	db database.Store,
	chatID, modelConfigID, fileID uuid.UUID,
) {
	t.Helper()

	parts := []codersdk.ChatMessagePart{
		codersdk.ChatMessageText("hello world"),
		codersdk.ChatMessageReasoning("thinking..."),
		codersdk.ChatMessageToolCall("call_abc", "demo_tool", json.RawMessage(`{"arg":"value"}`)),
		codersdk.ChatMessageToolResult("call_abc", "demo_tool", json.RawMessage(`{"ok":true}`), false, false),
		{
			Type:      codersdk.ChatMessagePartTypeFile,
			FileID:    uuid.NullUUID{UUID: fileID, Valid: true},
			MediaType: "text/plain",
		},
		codersdk.ChatMessageFileReference("README.md", 1, 10, "example content"),
		{
			Type:            codersdk.ChatMessagePartTypeContextFile,
			ContextFilePath: "AGENTS.md",
		},
	}
	content, err := chatprompt.MarshalParts(parts)
	require.NoError(t, err)

	_, err = db.InsertChatMessages(dbauthz.AsSystemRestricted(ctx), database.InsertChatMessagesParams{
		ChatID:              chatID,
		CreatedBy:           []uuid.UUID{uuid.Nil},
		ModelConfigID:       []uuid.UUID{modelConfigID},
		Role:                []database.ChatMessageRole{database.ChatMessageRoleAssistant},
		ContentVersion:      []int16{chatprompt.CurrentContentVersion},
		Content:             []string{string(content.RawMessage)},
		Visibility:          []database.ChatMessageVisibility{database.ChatMessageVisibilityBoth},
		InputTokens:         []int64{0},
		OutputTokens:        []int64{0},
		TotalTokens:         []int64{0},
		ReasoningTokens:     []int64{0},
		CacheCreationTokens: []int64{0},
		CacheReadTokens:     []int64{0},
		ContextLimit:        []int64{0},
		Compressed:          []bool{false},
		TotalCostMicros:     []int64{0},
		RuntimeMs:           []int64{0},
	})
	require.NoError(t, err)
}

// insertSharedChatFile inserts a chat_files row and links it to the chat
// so the owner's Chat.Files is populated.
func insertSharedChatFile(
	ctx context.Context,
	t *testing.T,
	db database.Store,
	orgID, ownerID, chatID uuid.UUID,
) uuid.UUID {
	t.Helper()

	//nolint:gocritic // Using AsChatd to mimic the chatd background worker that normally inserts files.
	chatdCtx := dbauthz.AsChatd(ctx)
	row, err := db.InsertChatFile(chatdCtx, database.InsertChatFileParams{
		OwnerID:        ownerID,
		OrganizationID: orgID,
		Name:           "shared.md",
		Mimetype:       "text/markdown",
		Data:           []byte("# Shared"),
	})
	require.NoError(t, err)
	rejected, err := db.LinkChatFiles(chatdCtx, database.LinkChatFilesParams{
		ChatID:       chatID,
		MaxFileLinks: int32(codersdk.MaxChatFileIDs),
		FileIds:      []uuid.UUID{row.ID},
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), rejected)
	return row.ID
}

// typeCounts builds a multiset of part types keyed by redacted_type
// where applicable, so tests can assert ordering + redaction exactly.
func typeCounts(parts []codersdk.ChatMessagePartForViewer) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Type == codersdk.ChatMessagePartTypeRedacted {
			out = append(out, "redacted:"+string(p.RedactedType))
			continue
		}
		out = append(out, string(p.Type))
	}
	return out
}

func TestGetChatMessages_OwnerSeesEverything(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "owner sees everything")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	resp, err := ownerClient.GetChatMessages(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessage(t, resp.Messages)
	types := make([]string, 0, len(assistant.Content))
	for _, p := range assistant.Content {
		types = append(types, string(p.Type))
	}
	require.Equal(t, []string{"text", "reasoning", "tool-call", "tool-result", "file", "file-reference", "context-file"}, types)

	chatRes, err := ownerClient.GetChat(ctx, chat.ID)
	require.NoError(t, err)
	require.Len(t, chatRes.Files, 1)
}

func TestGetChatMessages_SharedViewer_NothingExtra(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "shared viewer default")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	resp, err := viewerClient.GetChatMessagesForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessageForViewer(t, resp.Messages)
	require.Equal(t,
		[]string{
			"text",
			"reasoning",
			"redacted:tool-call",
			"redacted:tool-result",
			"redacted:file",
			"redacted:file-reference",
			"redacted:context-file",
		},
		typeCounts(assistant.Content),
	)

	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+chat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var chatView codersdk.ChatForViewer
	require.NoError(t, json.NewDecoder(res.Body).Decode(&chatView))
	require.Empty(t, chatView.Files)
}

func TestGetChatMessages_SharedViewer_ToolsOnly(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "tools only viewer")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead, ShareToolCalls: true},
		},
	})
	require.NoError(t, err)

	resp, err := viewerClient.GetChatMessagesForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessageForViewer(t, resp.Messages)
	require.Equal(t,
		[]string{
			"text",
			"reasoning",
			"tool-call",
			"tool-result",
			"redacted:file",
			"redacted:file-reference",
			"redacted:context-file",
		},
		typeCounts(assistant.Content),
	)

	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+chat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	var chatView codersdk.ChatForViewer
	require.NoError(t, json.NewDecoder(res.Body).Decode(&chatView))
	require.Empty(t, chatView.Files)
}

func TestGetChatMessages_SharedViewer_AttachmentsOnly(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "attachments only viewer")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead, ShareAttachments: true},
		},
	})
	require.NoError(t, err)

	resp, err := viewerClient.GetChatMessagesForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessageForViewer(t, resp.Messages)
	require.Equal(t,
		[]string{
			"text",
			"reasoning",
			"redacted:tool-call",
			"redacted:tool-result",
			"file",
			"file-reference",
			"context-file",
		},
		typeCounts(assistant.Content),
	)

	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+chat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	var chatView codersdk.ChatForViewer
	require.NoError(t, json.NewDecoder(res.Body).Decode(&chatView))
	require.Len(t, chatView.Files, 1)
}

func TestGetChatMessages_GroupEntryFlags(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	group := dbgen.Group(t, db, database.Group{OrganizationID: firstUser.OrganizationID})
	dbgen.GroupMember(t, db, database.GroupMemberTable{GroupID: group.ID, UserID: viewer.ID})

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "group entry flags")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleRead, ShareToolCalls: true},
		},
	})
	require.NoError(t, err)

	resp, err := viewerClient.GetChatMessagesForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessageForViewer(t, resp.Messages)
	require.Equal(t,
		[]string{
			"text",
			"reasoning",
			"tool-call",
			"tool-result",
			"redacted:file",
			"redacted:file-reference",
			"redacted:context-file",
		},
		typeCounts(assistant.Content),
	)

	// Group entry grants tool-calls only; Chat.Files must stay empty
	// because no entry grants ShareAttachments.
	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+chat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var chatView codersdk.ChatForViewer
	require.NoError(t, json.NewDecoder(res.Body).Decode(&chatView))
	require.Empty(t, chatView.Files, "viewer without ShareAttachments must not see chat Files")
}

func TestGetChatMessages_UnionAcrossEntries(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	group := dbgen.Group(t, db, database.Group{OrganizationID: firstUser.OrganizationID})
	dbgen.GroupMember(t, db, database.GroupMemberTable{GroupID: group.ID, UserID: viewer.ID})

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "union across entries")
	fileID := insertSharedChatFile(ctx, t, db, firstUser.OrganizationID, firstUser.UserID, chat.ID)
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, fileID)

	// Attribution: user entry contributes ShareAttachments, group entry
	// contributes ShareToolCalls. Union must unredact both halves.
	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead, ShareAttachments: true},
		},
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleRead, ShareToolCalls: true},
		},
	})
	require.NoError(t, err)

	resp, err := viewerClient.GetChatMessagesForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)

	assistant := findAssistantMessageForViewer(t, resp.Messages)
	require.Equal(t,
		[]string{
			"text",
			"reasoning",
			"tool-call",
			"tool-result",
			"file",
			"file-reference",
			"context-file",
		},
		typeCounts(assistant.Content),
	)

	// Chat.Files must surface when ShareAttachments is granted by the
	// user entry — even though the group entry is attachments-off.
	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+chat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var chatView codersdk.ChatForViewer
	require.NoError(t, json.NewDecoder(res.Body).Decode(&chatView))
	require.Len(t, chatView.Files, 1,
		"viewer with ShareAttachments via user entry must see chat Files")
}

func TestStreamChat_SharedViewerFiltersToolParts(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "stream viewer filter")
	insertShareTestAssistantMessage(ctx, t, db, chat.ID, modelConfig.ID, uuid.New())

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	events, closer, err := viewerClient.StreamChatForViewer(ctx, chat.ID, nil)
	require.NoError(t, err)
	defer closer.Close()

	seenRedactedTool := false
	seenRedactedAttachment := false
	for !(seenRedactedTool && seenRedactedAttachment) {
		select {
		case <-ctx.Done():
			require.FailNow(t,
				"timed out waiting for redacted tool + attachment parts on viewer stream",
				"seenTool=%v seenAttachment=%v", seenRedactedTool, seenRedactedAttachment)
		case event, ok := <-events:
			require.True(t, ok, "viewer stream closed before expected event")
			require.NotEqual(t, codersdk.ChatStreamEventTypeError, event.Type)

			if event.Type != codersdk.ChatStreamEventTypeMessage ||
				event.Message == nil ||
				event.Message.Role != codersdk.ChatMessageRoleAssistant {
				continue
			}
			for _, p := range event.Message.Content {
				require.NotEqual(t, codersdk.ChatMessagePartTypeToolCall, p.Type,
					"viewer should never see an un-redacted tool-call part")
				require.NotEqual(t, codersdk.ChatMessagePartTypeToolResult, p.Type,
					"viewer should never see an un-redacted tool-result part")
				require.NotEqual(t, codersdk.ChatMessagePartTypeFile, p.Type,
					"viewer without ShareAttachments should never see an un-redacted file part")
				require.NotEqual(t, codersdk.ChatMessagePartTypeFileReference, p.Type,
					"viewer without ShareAttachments should never see a file-reference part")
				require.NotEqual(t, codersdk.ChatMessagePartTypeContextFile, p.Type,
					"viewer without ShareAttachments should never see a context-file part")

				if p.Type != codersdk.ChatMessagePartTypeRedacted {
					continue
				}
				switch p.RedactedType {
				case codersdk.ChatMessagePartTypeToolCall,
					codersdk.ChatMessagePartTypeToolResult:
					seenRedactedTool = true
				case codersdk.ChatMessagePartTypeFile,
					codersdk.ChatMessagePartTypeFileReference,
					codersdk.ChatMessagePartTypeContextFile:
					seenRedactedAttachment = true
				}
			}
		}
	}
}

func findAssistantMessage(t *testing.T, msgs []codersdk.ChatMessage) codersdk.ChatMessage {
	t.Helper()
	for _, m := range msgs {
		if m.Role == codersdk.ChatMessageRoleAssistant {
			return m
		}
	}
	require.FailNow(t, "no assistant message found")
	return codersdk.ChatMessage{}
}

func findAssistantMessageForViewer(t *testing.T, msgs []codersdk.ChatMessageForViewer) codersdk.ChatMessageForViewer {
	t.Helper()
	for _, m := range msgs {
		if m.Role == codersdk.ChatMessageRoleAssistant {
			return m
		}
	}
	require.FailNow(t, "no assistant message found")
	return codersdk.ChatMessageForViewer{}
}

// TestSubChatAccess_ViewerViaRootACL exercises the core promise of
// migration 000471: a viewer granted ChatRoleRead on a root chat can
// reach the sub-chat through the HTTP API. The stored user_acl on the
// sub-chat row is empty by design; the chats_with_acl view must supply
// the root ACL for dbauthz to authorize the viewer.
func TestSubChatAccess_ViewerViaRootACL(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	modelConfig := createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	root := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "root chat with viewer acl")

	subChat, err := db.InsertChat(dbauthz.AsSystemRestricted(ctx), database.InsertChatParams{
		OrganizationID:    firstUser.OrganizationID,
		Status:            database.ChatStatusWaiting,
		ClientType:        database.ChatClientTypeUi,
		OwnerID:           firstUser.UserID,
		LastModelConfigID: modelConfig.ID,
		Title:             "sub-chat inherits root acl",
		ParentChatID:      uuid.NullUUID{UUID: root.ID, Valid: true},
		RootChatID:        uuid.NullUUID{UUID: root.ID, Valid: true},
	})
	require.NoError(t, err)

	insertShareTestAssistantMessage(ctx, t, db, subChat.ID, modelConfig.ID, uuid.Nil)

	err = ownerClient.UpdateChatACL(ctx, root.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.NoError(t, err)

	// (1) GET /chats/{subChatID} must return 200 for the viewer.
	res, err := viewerClient.Request(ctx, http.MethodGet, "/api/experimental/chats/"+subChat.ID.String(), nil)
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode,
		"viewer with root-chat ChatRoleRead must reach the sub-chat via the effective ACL")

	// (2) GET /chats/{subChatID}/messages must return 200 with the
	// seeded assistant message.
	msgs, err := viewerClient.GetChatMessagesForViewer(ctx, subChat.ID, nil)
	require.NoError(t, err)
	_ = findAssistantMessageForViewer(t, msgs.Messages)

	// (3) Write path still rejects: sub-chats cannot have their own
	// ACL set, even by the owner.
	err = ownerClient.UpdateChatACL(ctx, subChat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	sdkErr := requireSDKError(t, err, http.StatusBadRequest)
	require.Contains(t, sdkErr.Message, "root chats")
}

func chatIDSet(chats []codersdk.Chat) map[uuid.UUID]struct{} {
	ids := make(map[uuid.UUID]struct{}, len(chats))
	for _, c := range chats {
		ids[c.ID] = struct{}{}
	}
	return ids
}

// TestChatSharingDisabled mirrors TestWorkspaceSharingDisabled: when
// DisableChatSharing is set at startup, viewers with a stored chat ACL
// entry are denied access. When it is unset the ACL is enforced.
//
//nolint:tparallel,paralleltest // Subtests modify a package global (rbac.chatACLDisabled).
func TestChatSharingDisabled(t *testing.T) {
	t.Run("CanAccessWhenEnabled", func(t *testing.T) {
		ctx := testutil.Context(t, testutil.WaitLong)
		ownerClient, _ := newChatClientWithDatabase(t)
		firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
		_ = createChatModelConfig(t, ownerClient)

		viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
		viewerClient := codersdk.NewExperimentalClient(viewerRaw)

		chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "chat sharing enabled")
		err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
			UserRoles: map[string]codersdk.ChatShareEntry{
				viewer.ID.String(): {Role: codersdk.ChatRoleRead},
			},
		})
		require.NoError(t, err)

		_, err = viewerClient.GetChat(ctx, chat.ID)
		require.NoError(t, err, "shared viewer must reach chat when sharing is enabled")
	})

	t.Run("NoAccessWhenDisabled", func(t *testing.T) {
		t.Cleanup(func() {
			rbac.ReloadBuiltinRoles(nil)
		})

		ctx := testutil.Context(t, testutil.WaitLong)
		dv := chatDeploymentValues(t)
		dv.DisableChatSharing = true

		rawClient, db := coderdtest.NewWithDatabase(t, &coderdtest.Options{
			DeploymentValues: dv,
		})
		ownerClient := codersdk.NewExperimentalClient(rawClient)
		firstUser := coderdtest.CreateFirstUser(t, rawClient)
		_ = createChatModelConfig(t, ownerClient)

		viewerRaw, viewer := coderdtest.CreateAnotherUser(t, rawClient, firstUser.OrganizationID)
		viewerClient := codersdk.NewExperimentalClient(viewerRaw)

		chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "chat sharing disabled")

		// Seed the ACL directly as an owner subject: the HTTP UpdateChatACL
		// endpoint rejects patches when chat sharing is disabled for the
		// deployment, and the system-restricted subject lacks chat.share.
		//nolint:gocritic // Owner context is needed to seed ACL in test setup.
		ownerRoles, err := rbac.RoleIdentifiers{rbac.RoleOwner()}.Expand()
		require.NoError(t, err)
		ownerCtx := dbauthz.As(ctx, rbac.Subject{
			ID:    "owner",
			Roles: rbac.Roles(ownerRoles),
			Scope: rbac.ExpandableScope(rbac.ScopeAll),
		})
		require.NoError(t, db.UpdateChatACLByID(ownerCtx, database.UpdateChatACLByIDParams{
			ID: chat.ID,
			UserACL: database.ChatACL{
				viewer.ID.String(): database.ChatACLEntry{Permissions: []policy.Action{policy.ActionRead}},
			},
			GroupACL: database.ChatACL{},
		}))

		_, err = viewerClient.GetChat(ctx, chat.ID)
		sdkErr := requireSDKError(t, err, http.StatusNotFound)
		require.NotNil(t, sdkErr)
	})
}

// TestChatACL_NonOwnerForbidden mirrors TestDeleteWorkspaceACL/SharedUsersCannot:
// a viewer holding ChatRoleRead may GET the ACL but must not be able to
// mutate it. Users with no ACL entry at all get 404 on read.
func TestChatACL_NonOwnerForbidden(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, _ := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	viewerRaw, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	viewerClient := codersdk.NewExperimentalClient(viewerRaw)

	strangerRaw, stranger := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	strangerClient := codersdk.NewExperimentalClient(strangerRaw)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "non-owner boundary")
	require.NoError(t, ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	}))

	// Viewer with ChatRoleRead can read the ACL.
	acl, err := viewerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err, "viewer with ChatRoleRead must be allowed to GET the ACL")
	require.Len(t, acl.Users, 1)
	require.Equal(t, viewer.ID, acl.Users[0].ID)

	// Viewer may not PATCH the ACL. Target a third user so the
	// self-edit guard does not short-circuit first.
	err = viewerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			stranger.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	require.Error(t, err, "non-owner must not be able to PATCH the ACL")
	var patchErr *codersdk.Error
	require.ErrorAs(t, err, &patchErr)
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, patchErr.StatusCode())

	// Viewer may not DELETE the ACL.
	err = viewerClient.DeleteChatACL(ctx, chat.ID)
	require.Error(t, err, "non-owner must not be able to DELETE the ACL")
	var delErr *codersdk.Error
	require.ErrorAs(t, err, &delErr)
	require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, delErr.StatusCode())

	// Stranger outside the ACL gets 404 on read.
	_, err = strangerClient.ChatACL(ctx, chat.ID)
	require.Error(t, err, "stranger must not see the chat at all")
	var getErr *codersdk.Error
	require.ErrorAs(t, err, &getErr)
	require.Equal(t, http.StatusNotFound, getErr.StatusCode())
}

// TestPatchChatACL_CannotChangeOwnRole mirrors
// TestUpdateWorkspaceACL/CannotChangeOwnRole: the owner cannot demote
// themselves via the ACL patch endpoint.
func TestPatchChatACL_CannotChangeOwnRole(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, _ := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "cannot change own role")

	err := ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			firstUser.UserID.String(): {Role: codersdk.ChatRoleRead},
		},
	})
	sdkErr := requireSDKError(t, err, http.StatusBadRequest)
	require.NotNil(t, sdkErr)
	require.Contains(t, sdkErr.Message, "cannot change your own chat sharing role")
}

// TestPatchChatACL_RemovesEntryViaDeletedRole pins the empty-string
// ChatRoleDeleted sentinel as the removal contract: a PATCH with that
// role empties the entry on both user and group maps.
func TestPatchChatACL_RemovesEntryViaDeletedRole(t *testing.T) {
	t.Parallel()

	ctx := testutil.Context(t, testutil.WaitLong)
	ownerClient, db := newChatClientWithDatabase(t)
	firstUser := coderdtest.CreateFirstUser(t, ownerClient.Client)
	_ = createChatModelConfig(t, ownerClient)

	_, viewer := coderdtest.CreateAnotherUser(t, ownerClient.Client, firstUser.OrganizationID)
	group := dbgen.Group(t, db, database.Group{OrganizationID: firstUser.OrganizationID})
	dbgen.GroupMember(t, db, database.GroupMemberTable{GroupID: group.ID, UserID: viewer.ID})

	chat := createSharedChat(ctx, t, ownerClient, firstUser.OrganizationID, "remove via deleted role")

	require.NoError(t, ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleRead},
		},
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleRead},
		},
	}))

	acl, err := ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)
	require.Len(t, acl.Users, 1)
	require.Len(t, acl.Groups, 1)

	require.NoError(t, ownerClient.UpdateChatACL(ctx, chat.ID, codersdk.UpdateChatACL{
		UserRoles: map[string]codersdk.ChatShareEntry{
			viewer.ID.String(): {Role: codersdk.ChatRoleDeleted},
		},
		GroupRoles: map[string]codersdk.ChatShareEntry{
			group.ID.String(): {Role: codersdk.ChatRoleDeleted},
		},
	}))

	acl, err = ownerClient.ChatACL(ctx, chat.ID)
	require.NoError(t, err)
	require.Empty(t, acl.Users, "ChatRoleDeleted must remove the user entry")
	require.Empty(t, acl.Groups, "ChatRoleDeleted must remove the group entry")
}
