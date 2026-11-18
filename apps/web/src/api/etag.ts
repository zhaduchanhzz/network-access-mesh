// Khóa lạc quan (§6.1, §13.1): GET của tài nguyên có phiên bản trả `ETag`; lệnh sửa gửi lại đúng giá trị đó trong
// `If-Match`. Thiếu `If-Match` ⇒ 428 precondition_required (lỗi lập trình của client); tài nguyên đã đổi ⇒
// 412 precondition_failed — UI tải lại bản mới và để người dùng quyết định lại, không tự ghi đè.
import { callWithResponse } from "./client";
import { ApiError } from "./problem";

export interface Versioned<T> {
  data: T;
  /** giá trị ETag nguyên văn (kể cả dấu nháy, tiền tố W/) — null khi server không gửi */
  etag: string | null;
}

/** GET kèm ETag của phản hồi. */
export async function callWithETag<T>(
  pending: Parameters<typeof callWithResponse<T>>[0],
  opts: { notify?: boolean } = {},
): Promise<Versioned<T>> {
  const r = await callWithResponse(pending, opts);
  return { data: r.data, etag: r.headers.get("ETag") };
}

/** Header If-Match cho lệnh sửa. Không có ETag ⇒ ném lỗi ngay (không gửi request sẽ chắc chắn bị 428). */
export function ifMatch(etag: string | null | undefined): { "If-Match": string } {
  if (!etag || etag === "*") throw new Error("ifMatch: thiếu ETag của bản đã đọc (không dùng `*`)");
  return { "If-Match": etag };
}

/** 412: bản đang sửa đã cũ — tải lại rồi cho người dùng thao tác lại. */
export function isStaleVersion(error: unknown): boolean {
  return error instanceof ApiError && error.code === "precondition_failed";
}

/** 428: request ghi thiếu If-Match — lỗi lập trình, không phải lỗi của người dùng. */
export function isMissingVersion(error: unknown): boolean {
  return error instanceof ApiError && error.code === "precondition_required";
}
