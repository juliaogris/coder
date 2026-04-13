package chattool_test

import (
	"context"
	"testing"

	"charm.land/fantasy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/coderd/x/chatd/chattool"
	"github.com/coder/coder/v2/codersdk/workspacesdk"
	"github.com/coder/coder/v2/codersdk/workspacesdk/agentconnmock"
	"github.com/coder/quartz"
)

func TestComputerUseTool_Info(t *testing.T) {
	t.Parallel()

	geometry := workspacesdk.DefaultDesktopGeometry()
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, nil, nil, quartz.NewReal())
	info := tool.Info()
	assert.Equal(t, "computer", info.Name)
	assert.NotEmpty(t, info.Description)
}

func TestComputerUseProviderTool(t *testing.T) {
	t.Parallel()

	geometry := workspacesdk.DefaultDesktopGeometry()
	def := chattool.ComputerUseProviderTool(geometry.DeclaredWidth, geometry.DeclaredHeight)
	pdt, ok := def.(fantasy.ProviderDefinedTool)
	require.True(t, ok, "ComputerUseProviderTool should return a ProviderDefinedTool")
	assert.Contains(t, pdt.ID, "computer")
	assert.Equal(t, "computer", pdt.Name)
	assert.Equal(t, int64(geometry.DeclaredWidth), pdt.Args["display_width_px"])
	assert.Equal(t, int64(geometry.DeclaredHeight), pdt.Args["display_height_px"])
}

func TestComputerUseProviderTool_PrefersDeclaredGeometry(t *testing.T) {
	t.Parallel()

	geometry := workspacesdk.NewDesktopGeometry(1920, 1080)
	def := chattool.ComputerUseProviderTool(geometry.DeclaredWidth, geometry.DeclaredHeight)
	pdt, ok := def.(fantasy.ProviderDefinedTool)
	require.True(t, ok, "ComputerUseProviderTool should return a ProviderDefinedTool")
	assert.Equal(t, int64(1280), pdt.Args["display_width_px"])
	assert.Equal(t, int64(720), pdt.Args["display_height_px"])
}

func TestComputerUseTool_Run_Screenshot(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).DoAndReturn(func(_ context.Context, action workspacesdk.DesktopAction) (workspacesdk.DesktopActionResponse, error) {
		require.NotNil(t, action.ScaledWidth)
		require.NotNil(t, action.ScaledHeight)
		assert.Equal(t, geometry.DeclaredWidth, *action.ScaledWidth)
		assert.Equal(t, geometry.DeclaredHeight, *action.ScaledHeight)
		return workspacesdk.DesktopActionResponse{
			Output:           "screenshot",
			ScreenshotData:   "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4n539HwAHFwLVF8kc1wAAAABJRU5ErkJggg==",
			ScreenshotWidth:  geometry.DeclaredWidth,
			ScreenshotHeight: geometry.DeclaredHeight,
		}, nil
	})

	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, func(_ context.Context, _ string, _ string, _ []byte) (uuid.UUID, error) {
		return uuid.MustParse("11111111-2222-3333-4444-555555555555"), nil
	}, quartz.NewReal())

	call := fantasy.ToolCall{
		ID:    "test-1",
		Name:  "computer",
		Input: `{"action":"screenshot"}`,
	}

	resp, err := tool.Run(context.Background(), call)
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.Equal(t, "image/png", resp.MediaType)
	assert.Equal(t, []byte("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4n539HwAHFwLVF8kc1wAAAABJRU5ErkJggg=="), resp.Data)
	assert.False(t, resp.IsError)
}

func TestComputerUseTool_Run_Screenshot_PersistsAttachment(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()
	const screenshotPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4n539HwAHFwLVF8kc1wAAAABJRU5ErkJggg=="

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).DoAndReturn(func(_ context.Context, action workspacesdk.DesktopAction) (workspacesdk.DesktopActionResponse, error) {
		require.Equal(t, "screenshot", action.Action)
		return workspacesdk.DesktopActionResponse{
			Output:           "screenshot",
			ScreenshotData:   screenshotPNG,
			ScreenshotWidth:  geometry.DeclaredWidth,
			ScreenshotHeight: geometry.DeclaredHeight,
		}, nil
	})

	var storedName string
	var storedType string
	var storedData []byte
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, func(_ context.Context, name string, mediaType string, data []byte) (uuid.UUID, error) {
		storedName = name
		storedType = mediaType
		storedData = append([]byte(nil), data...)
		return uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), nil
	}, quartz.NewReal())

	resp, err := tool.Run(context.Background(), fantasy.ToolCall{
		ID: "test-screenshot-persist", Name: "computer", Input: `{"action":"screenshot"}`,
	})
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.Equal(t, "image/png", resp.MediaType)
	assert.Equal(t, []byte(screenshotPNG), resp.Data)
	assert.Contains(t, storedName, "screenshot-")
	assert.Equal(t, "image/png", storedType)
	require.NotEmpty(t, storedData)

	attachments := chattool.AttachmentsFromMetadata(resp.Metadata)
	require.Len(t, attachments, 1)
	assert.Equal(t, uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), attachments[0].FileID)
	assert.Equal(t, "image/png", attachments[0].MimeType)
}

func TestComputerUseTool_Run_Screenshot_WithoutStoreFileReturnsError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, nil, quartz.NewReal())

	resp, err := tool.Run(context.Background(), fantasy.ToolCall{
		ID: "test-screenshot-no-store", Name: "computer", Input: `{"action":"screenshot"}`,
	})
	require.NoError(t, err)
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "file storage is not configured")
}

func TestComputerUseTool_Run_Screenshot_StoreErrorReturnsError(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()
	const screenshotPNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4n539HwAHFwLVF8kc1wAAAABJRU5ErkJggg=="

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).Return(workspacesdk.DesktopActionResponse{
		Output:           "screenshot",
		ScreenshotData:   screenshotPNG,
		ScreenshotWidth:  geometry.DeclaredWidth,
		ScreenshotHeight: geometry.DeclaredHeight,
	}, nil)

	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, func(_ context.Context, _ string, _ string, _ []byte) (uuid.UUID, error) {
		return uuid.Nil, xerrors.New("chat already has the maximum of 20 linked files")
	}, quartz.NewReal())

	resp, err := tool.Run(context.Background(), fantasy.ToolCall{
		ID: "test-screenshot-store-error", Name: "computer", Input: `{"action":"screenshot"}`,
	})
	require.NoError(t, err)
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "failed to store screenshot attachment")
	assert.Contains(t, resp.Content, "chat already has the maximum of 20 linked files")
}

func TestComputerUseTool_Run_WaitDoesNotPersistAttachment(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).Return(workspacesdk.DesktopActionResponse{
		Output:           "screenshot",
		ScreenshotData:   "after-wait",
		ScreenshotWidth:  geometry.DeclaredWidth,
		ScreenshotHeight: geometry.DeclaredHeight,
	}, nil)

	calledStore := false
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, func(_ context.Context, _ string, _ string, _ []byte) (uuid.UUID, error) {
		calledStore = true
		return uuid.Nil, nil
	}, quartz.NewReal())

	resp, err := tool.Run(context.Background(), fantasy.ToolCall{
		ID: "test-wait-no-persist", Name: "computer", Input: `{"action":"wait","duration":1}`,
	})
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.False(t, calledStore)
	assert.Empty(t, chattool.AttachmentsFromMetadata(resp.Metadata))
}

func TestComputerUseTool_Run_ActionFollowupScreenshotDoesNotPersistAttachment(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).Return(workspacesdk.DesktopActionResponse{Output: "left_click performed"}, nil)
	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).Return(workspacesdk.DesktopActionResponse{
		Output:           "screenshot",
		ScreenshotData:   "after-click",
		ScreenshotWidth:  geometry.DeclaredWidth,
		ScreenshotHeight: geometry.DeclaredHeight,
	}, nil)

	calledStore := false
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, func(_ context.Context, _ string, _ string, _ []byte) (uuid.UUID, error) {
		calledStore = true
		return uuid.Nil, nil
	}, quartz.NewReal())

	resp, err := tool.Run(context.Background(), fantasy.ToolCall{
		ID: "test-click-no-persist", Name: "computer", Input: `{"action":"left_click","coordinate":[100,200]}`,
	})
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.False(t, calledStore)
	assert.Empty(t, chattool.AttachmentsFromMetadata(resp.Metadata))
}

func TestComputerUseTool_Run_LeftClick(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).DoAndReturn(func(_ context.Context, action workspacesdk.DesktopAction) (workspacesdk.DesktopActionResponse, error) {
		require.NotNil(t, action.Coordinate)
		assert.Equal(t, [2]int{100, 200}, *action.Coordinate)
		require.NotNil(t, action.ScaledWidth)
		require.NotNil(t, action.ScaledHeight)
		assert.Equal(t, geometry.DeclaredWidth, *action.ScaledWidth)
		assert.Equal(t, geometry.DeclaredHeight, *action.ScaledHeight)
		return workspacesdk.DesktopActionResponse{Output: "left_click performed"}, nil
	})

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).DoAndReturn(func(_ context.Context, action workspacesdk.DesktopAction) (workspacesdk.DesktopActionResponse, error) {
		assert.Equal(t, "screenshot", action.Action)
		require.NotNil(t, action.ScaledWidth)
		require.NotNil(t, action.ScaledHeight)
		assert.Equal(t, geometry.DeclaredWidth, *action.ScaledWidth)
		assert.Equal(t, geometry.DeclaredHeight, *action.ScaledHeight)
		return workspacesdk.DesktopActionResponse{
			Output:           "screenshot",
			ScreenshotData:   "after-click",
			ScreenshotWidth:  geometry.DeclaredWidth,
			ScreenshotHeight: geometry.DeclaredHeight,
		}, nil
	})

	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, nil, quartz.NewReal())

	call := fantasy.ToolCall{
		ID:    "test-2",
		Name:  "computer",
		Input: `{"action":"left_click","coordinate":[100,200]}`,
	}

	resp, err := tool.Run(context.Background(), call)
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.Equal(t, []byte("after-click"), resp.Data)
}

func TestComputerUseTool_Run_Wait(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	mockConn := agentconnmock.NewMockAgentConn(ctrl)
	geometry := workspacesdk.DefaultDesktopGeometry()

	mockConn.EXPECT().ExecuteDesktopAction(
		gomock.Any(),
		gomock.AssignableToTypeOf(workspacesdk.DesktopAction{}),
	).DoAndReturn(func(_ context.Context, action workspacesdk.DesktopAction) (workspacesdk.DesktopActionResponse, error) {
		require.NotNil(t, action.ScaledWidth)
		require.NotNil(t, action.ScaledHeight)
		assert.Equal(t, geometry.DeclaredWidth, *action.ScaledWidth)
		assert.Equal(t, geometry.DeclaredHeight, *action.ScaledHeight)
		return workspacesdk.DesktopActionResponse{
			Output:           "screenshot",
			ScreenshotData:   "after-wait",
			ScreenshotWidth:  geometry.DeclaredWidth,
			ScreenshotHeight: geometry.DeclaredHeight,
		}, nil
	})

	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return mockConn, nil
	}, nil, quartz.NewReal())

	call := fantasy.ToolCall{
		ID:    "test-3",
		Name:  "computer",
		Input: `{"action":"wait","duration":10}`,
	}

	resp, err := tool.Run(context.Background(), call)
	require.NoError(t, err)
	assert.Equal(t, "image", resp.Type)
	assert.Equal(t, "image/png", resp.MediaType)
	assert.Equal(t, []byte("after-wait"), resp.Data)
	assert.False(t, resp.IsError)
}

func TestComputerUseTool_Run_ConnError(t *testing.T) {
	t.Parallel()

	geometry := workspacesdk.DefaultDesktopGeometry()
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return nil, xerrors.New("workspace not available")
	}, nil, quartz.NewReal())

	call := fantasy.ToolCall{
		ID:    "test-4",
		Name:  "computer",
		Input: `{"action":"screenshot"}`,
	}

	resp, err := tool.Run(context.Background(), call)
	require.NoError(t, err)
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "workspace not available")
}

func TestComputerUseTool_Run_InvalidInput(t *testing.T) {
	t.Parallel()

	geometry := workspacesdk.DefaultDesktopGeometry()
	tool := chattool.NewComputerUseTool(geometry.DeclaredWidth, geometry.DeclaredHeight, func(_ context.Context) (workspacesdk.AgentConn, error) {
		return nil, xerrors.New("should not be called")
	}, nil, quartz.NewReal())

	call := fantasy.ToolCall{
		ID:    "test-5",
		Name:  "computer",
		Input: `{invalid json`,
	}

	resp, err := tool.Run(context.Background(), call)
	require.NoError(t, err)
	assert.True(t, resp.IsError)
	assert.Contains(t, resp.Content, "invalid computer use input")
}
