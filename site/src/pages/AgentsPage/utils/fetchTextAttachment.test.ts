import {
	decodeInlineTextAttachment,
	fetchTextAttachmentContent,
	formatTextAttachmentPreview,
} from "./fetchTextAttachment";

const encodeUtf8Base64 = (value: string) => {
	const bytes = new TextEncoder().encode(value);
	return btoa(String.fromCharCode(...bytes));
};

describe("formatTextAttachmentPreview", () => {
	it('returns "Pasted text" for empty content', () => {
		expect(formatTextAttachmentPreview("")).toBe("Pasted text");
		expect(formatTextAttachmentPreview("   \n\t ")).toBe("Pasted text");
	});

	it("truncates longer text to the requested limit", () => {
		expect(formatTextAttachmentPreview("abcdefgh", 5)).toBe("abcde");
	});

	it("normalizes whitespace before building the preview", () => {
		expect(
			formatTextAttachmentPreview("  hello\n\nworld\tfrom\t tests  "),
		).toBe("hello world from tests");
	});

	it("preserves whole unicode code points when truncating emoji", () => {
		expect(formatTextAttachmentPreview("🙂🙂🙂", 2)).toBe("🙂🙂");
	});

	it("returns text shorter than the limit unchanged", () => {
		expect(formatTextAttachmentPreview("short text", 20)).toBe("short text");
	});
});

describe("decodeInlineTextAttachment", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("decodes base64-encoded UTF-8 text", () => {
		const text = "Hello 👋 café";

		expect(decodeInlineTextAttachment(encodeUtf8Base64(text))).toBe(text);
	});

	it("falls back to the raw string when base64 decoding fails", () => {
		const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
		const raw = "not-base64!";

		expect(decodeInlineTextAttachment(raw)).toBe(raw);
		expect(warn).toHaveBeenCalled();
	});
});

describe("fetchTextAttachmentContent", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("returns the response body when the fetch succeeds", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response("hello from the server", { status: 200 }),
		);

		await expect(fetchTextAttachmentContent("file-1")).resolves.toBe(
			"hello from the server",
		);
		expect(globalThis.fetch).toHaveBeenCalledWith(
			"/api/experimental/chats/files/file-1",
			expect.objectContaining({ signal: undefined }),
		);
	});

	it("includes the HTTP status in fetch errors", async () => {
		vi.spyOn(globalThis, "fetch").mockResolvedValue(
			new Response("nope", { status: 503 }),
		);

		await expect(fetchTextAttachmentContent("file-2")).rejects.toThrow(
			"Failed to fetch file (503)",
		);
	});
});
