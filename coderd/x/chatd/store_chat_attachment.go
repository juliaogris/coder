package chatd

import (
	"context"

	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/database"
	"github.com/coder/coder/v2/coderd/x/chatd/chattool"
	"github.com/coder/coder/v2/codersdk"
)

func (p *Server) newStoreChatAttachmentFunc(workspaceCtx *turnWorkspaceContext) chattool.StoreFileFunc {
	return chattool.StoreFileFunc(func(
		ctx context.Context,
		name string,
		mediaType string,
		data []byte,
	) (uuid.UUID, error) {
		workspaceCtx.chatStateMu.Lock()
		chatSnapshot := *workspaceCtx.currentChat
		workspaceCtx.chatStateMu.Unlock()

		return p.storeChatAttachment(ctx, chatSnapshot, name, mediaType, data)
	})
}

func (p *Server) storeChatAttachment(
	ctx context.Context,
	chatSnapshot database.Chat,
	name string,
	mediaType string,
	data []byte,
) (uuid.UUID, error) {
	if !chatSnapshot.WorkspaceID.Valid {
		return uuid.Nil, xerrors.New("no workspace is associated with this chat. Use the create_workspace tool to create one")
	}

	// Insert and link in one transaction so a cap rejection or linking
	// failure does not leave behind an unlinked chat file row.
	var storedID uuid.UUID
	err := p.db.InTx(func(tx database.Store) error {
		ws, err := tx.GetWorkspaceByID(ctx, chatSnapshot.WorkspaceID.UUID)
		if err != nil {
			return xerrors.Errorf("resolve workspace: %w", err)
		}

		row, err := tx.InsertChatFile(ctx, database.InsertChatFileParams{
			OwnerID:        chatSnapshot.OwnerID,
			OrganizationID: ws.OrganizationID,
			Name:           name,
			Mimetype:       mediaType,
			Data:           data,
		})
		if err != nil {
			return xerrors.Errorf("insert chat file: %w", err)
		}

		rejected, err := tx.LinkChatFiles(ctx, database.LinkChatFilesParams{
			ChatID:       chatSnapshot.ID,
			MaxFileLinks: int32(codersdk.MaxChatFileIDs),
			FileIds:      []uuid.UUID{row.ID},
		})
		if err != nil {
			return xerrors.Errorf("link chat file: %w", err)
		}
		if rejected > 0 {
			return xerrors.Errorf("chat already has the maximum of %d linked files", codersdk.MaxChatFileIDs)
		}

		storedID = row.ID
		return nil
	}, database.DefaultTXOptions().WithID("store_chat_attachment"))
	if err != nil {
		return uuid.Nil, err
	}
	return storedID, nil
}
