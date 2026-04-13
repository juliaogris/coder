package chattool

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"

	"charm.land/fantasy"
	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/chatfiles"
	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/coder/v2/codersdk/workspacesdk"
)

const (
	maxAttachmentSize = 10 << 20 // 10 MiB
	maxAttachmentName = 255
)

// allowedAttachmentMimeTypes is the first-ship allowlist for agent-created
// durable chat attachments. Text-like subtypes are refined before this check so
// safe content can be stored as text/plain, text/markdown, text/csv, or
// application/json while SVG stays blocked.
var allowedAttachmentMimeTypes = map[string]bool{
	"image/png":        true,
	"image/jpeg":       true,
	"image/gif":        true,
	"image/webp":       true,
	"text/plain":       true,
	"text/markdown":    true,
	"text/csv":         true,
	"application/json": true,
	"application/pdf":  true,
	"image/svg+xml":    false,
}

// StoreFileFunc persists a chat attachment and returns its durable ID.
type StoreFileFunc func(ctx context.Context, name string, mediaType string, data []byte) (uuid.UUID, error)

// AttachmentMetadata identifies a durable chat attachment that should be
// promoted into a standard file message part for the user.
//
// MimeType matches the stored file MIME type even though the serialized tool
// metadata uses the existing `media_type` field name shared with chat parts.
type AttachmentMetadata struct {
	FileID   uuid.UUID `json:"file_id"`
	MimeType string    `json:"media_type"`
	Name     string    `json:"name,omitempty"`
}

type attachmentResponseMetadata struct {
	Attachments []AttachmentMetadata `json:"attachments,omitempty"`
}

func isAllowedAttachmentMimeType(mimeType string) bool {
	allowed, ok := allowedAttachmentMimeTypes[mimeType]
	return ok && allowed
}

func refineTextAttachmentMimeType(name string, data []byte, _ string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".json":
		if json.Valid(data) {
			return "application/json"
		}
	case ".md", ".markdown":
		return "text/markdown"
	case ".csv":
		return "text/csv"
	}
	return "text/plain"
}

func isBlockedSVGAttachment(name string, mimeType string, data []byte) bool {
	if !chatfiles.IsSVGContent(data) {
		return false
	}

	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".svg", ".svgz":
		return true
	}

	switch mimeType {
	case "application/xml", "text/xml", "image/svg+xml":
		return true
	default:
		return false
	}
}

func detectAttachmentMimeType(name string, data []byte) string {
	mimeType := chatfiles.BaseMediaType(chatfiles.DetectContentType(data))
	if isBlockedSVGAttachment(name, mimeType, data) {
		return "image/svg+xml"
	}

	switch {
	case strings.HasPrefix(mimeType, "text/"):
		return refineTextAttachmentMimeType(name, data, mimeType)
	case mimeType == "application/xml":
		return "text/plain"
	default:
		return mimeType
	}
}

func storeAttachmentData(
	ctx context.Context,
	storeFile StoreFileFunc,
	name string,
	detectName string,
	data []byte,
) (AttachmentMetadata, error) {
	if storeFile == nil {
		return AttachmentMetadata{}, xerrors.New("file storage is not configured")
	}
	if len(data) == 0 {
		return AttachmentMetadata{}, xerrors.New("attachment is empty")
	}
	if len(data) > maxAttachmentSize {
		return AttachmentMetadata{}, xerrors.Errorf("attachment exceeds %d MiB size limit", maxAttachmentSize>>20)
	}
	if strings.TrimSpace(detectName) == "" {
		detectName = name
	}
	mimeType := detectAttachmentMimeType(detectName, data)
	if !isAllowedAttachmentMimeType(mimeType) {
		return AttachmentMetadata{}, xerrors.Errorf("unsupported attachment type %q", mimeType)
	}
	name = truncateRunes(strings.TrimSpace(name), maxAttachmentName)
	fileID, err := storeFile(ctx, name, mimeType, data)
	if err != nil {
		return AttachmentMetadata{}, err
	}
	return AttachmentMetadata{
		FileID:   fileID,
		MimeType: mimeType,
		Name:     name,
	}, nil
}

func storeWorkspaceAttachment(
	ctx context.Context,
	conn workspacesdk.AgentConn,
	path string,
	name string,
	storeFile StoreFileFunc,
) (AttachmentMetadata, int, error) {
	if conn == nil {
		return AttachmentMetadata{}, 0, xerrors.New("workspace connection is not configured")
	}
	if strings.TrimSpace(path) == "" {
		return AttachmentMetadata{}, 0, xerrors.New("path is required")
	}
	if !filepath.IsAbs(path) {
		return AttachmentMetadata{}, 0, xerrors.New("path must be absolute")
	}
	reader, _, err := conn.ReadFile(ctx, path, 0, maxAttachmentSize+1)
	if err != nil {
		return AttachmentMetadata{}, 0, err
	}
	defer reader.Close()

	data, err := io.ReadAll(reader)
	if err != nil {
		return AttachmentMetadata{}, 0, err
	}
	if len(data) > maxAttachmentSize {
		return AttachmentMetadata{}, 0, xerrors.Errorf("attachment exceeds %d MiB size limit", maxAttachmentSize>>20)
	}
	if strings.TrimSpace(name) == "" {
		name = filepath.Base(path)
	}
	attachment, err := storeAttachmentData(ctx, storeFile, name, path, data)
	if err != nil {
		return AttachmentMetadata{}, 0, err
	}
	return attachment, len(data), nil
}

func storeScreenshotAttachment(
	ctx context.Context,
	storeFile StoreFileFunc,
	name string,
	encodedPNG string,
) (AttachmentMetadata, error) {
	if strings.TrimSpace(encodedPNG) == "" {
		return AttachmentMetadata{}, xerrors.New("screenshot data is empty")
	}
	data, err := base64.StdEncoding.DecodeString(encodedPNG)
	if err != nil {
		return AttachmentMetadata{}, xerrors.Errorf("decode screenshot: %w", err)
	}
	if strings.TrimSpace(name) == "" {
		name = "screenshot.png"
	}
	return storeAttachmentData(ctx, storeFile, name, name, data)
}

func responseWithAttachments(
	response fantasy.ToolResponse,
	attachments ...AttachmentMetadata,
) fantasy.ToolResponse {
	if len(attachments) == 0 {
		return response
	}
	return fantasy.WithResponseMetadata(response, attachmentResponseMetadata{
		Attachments: attachments,
	})
}

// WithAttachments stores durable attachment metadata on a tool response so the
// persistence layer can promote the files into assistant chat attachments.
func WithAttachments(
	response fantasy.ToolResponse,
	attachments ...AttachmentMetadata,
) fantasy.ToolResponse {
	return responseWithAttachments(response, attachments...)
}

// AttachmentsFromMetadata decodes durable attachment metadata from a tool
// response so the persistence layer can promote them into assistant file parts.
func AttachmentsFromMetadata(metadata string) []AttachmentMetadata {
	if strings.TrimSpace(metadata) == "" {
		return nil
	}
	var decoded attachmentResponseMetadata
	if err := json.Unmarshal([]byte(metadata), &decoded); err != nil {
		return nil
	}
	result := make([]AttachmentMetadata, 0, len(decoded.Attachments))
	for _, attachment := range decoded.Attachments {
		if attachment.FileID == uuid.Nil || attachment.MimeType == "" {
			continue
		}
		result = append(result, attachment)
	}
	return result
}

// AttachmentPartsFromMetadata converts response metadata into standard file
// message parts so the chat transcript can render them like uploaded files.
func AttachmentPartsFromMetadata(metadata string) []codersdk.ChatMessagePart {
	attachments := AttachmentsFromMetadata(metadata)
	if len(attachments) == 0 {
		return nil
	}
	parts := make([]codersdk.ChatMessagePart, 0, len(attachments))
	for _, attachment := range attachments {
		parts = append(parts, codersdk.ChatMessageFile(
			attachment.FileID,
			attachment.MimeType,
			attachment.Name,
		))
	}
	return parts
}
