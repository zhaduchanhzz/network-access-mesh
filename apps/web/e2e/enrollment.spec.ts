// Luồng enrollment (P4-T06 backend, P4-T07 edge /register/*, P4-T08 UI) — CHƯA gộp vào nhánh này. Chỗ chừa sẵn cho
// G4b: mỗi ca dưới đây là `test.fixme` có lý do; khi P4-T06/07/08 vào, thay thân test bằng luồng thật (hai vai trò,
// hai ngôn ngữ, axe) và bỏ fixme. Hiện tại mục điều hướng enroll/enrollment-keys được tenant.spec.ts kiểm ở trạng thái
// "chưa khả dụng".
import { test } from "./support";

const PENDING = "P4-T06/P4-T07/P4-T08 (enrollment) chưa gộp — bổ sung khi các task này vào main";

test.describe("enrollment (chừa chỗ)", () => {
  test.fixme("End User: wizard enrollment theo OS (Windows/macOS/Linux/iOS/Android) + axe", () => {
    test.info().annotations.push({ type: "pending", description: PENDING });
  });
  test.fixme("End User: trang claim web-auth (mã enrollment trong hostname, yêu cầu đang chờ cùng phiên)", () => {
    test.info().annotations.push({ type: "pending", description: PENDING });
  });
  test.fixme("Admin: phát hành pre-auth key — key hiển thị MỘT lần, không còn trong DOM/storage sau khi đóng", () => {
    test.info().annotations.push({ type: "pending", description: PENDING });
  });
  test.fixme("Admin: hàng chờ duyệt yêu cầu enrollment (approve/reject/issue) + step-up", () => {
    test.info().annotations.push({ type: "pending", description: PENDING });
  });
  test.fixme("End-to-end với client thật: claim → node đăng ký → thiết bị hiện trong Devices (trạng thái hai pha)", () => {
    test.info().annotations.push({ type: "pending", description: PENDING });
  });
});
