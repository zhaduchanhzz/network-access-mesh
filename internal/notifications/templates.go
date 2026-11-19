package notifications

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// template is the subject and plain-text body of one kind in one locale. Templates are fixed text plus fields of the
// payload (checked at Enqueue: the kind's fields only, no secret, no URL) and the platform's own links (portal_url,
// console_url — built from MG_BASE_DOMAIN, never from the payload). Missing fields are an error (missingkey=error).
type mailTemplate struct{ subject, body string }

// footer of every e-mail, per locale.
var footers = map[string]string{
	LocaleVI: "\n\n—\nThư tự động của MeshGuard; vui lòng không trả lời. Xem mọi thông báo trong Portal: {{.portal_url}}\n" +
		"MeshGuard không bao giờ hỏi mật khẩu, mã xác thực hay khóa qua email.\n",
	LocaleEN: "\n\n—\nAutomated message from MeshGuard; please do not reply. All notifications are in the Portal: {{.portal_url}}\n" +
		"MeshGuard never asks for passwords, verification codes or keys by e-mail.\n",
}

var catalog = map[Kind]map[string]mailTemplate{
	KindTenantActivated: {
		LocaleVI: {"[MeshGuard] Tenant {{.tenant_name}} đã sẵn sàng",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) đã được kích hoạt và sẵn sàng sử dụng.\n\nĐăng nhập Portal để mời thành viên và thêm thiết bị: {{.portal_url}}"},
		LocaleEN: {"[MeshGuard] Tenant {{.tenant_name}} is ready",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) has been activated and is ready to use.\n\nSign in to the Portal to invite members and add devices: {{.portal_url}}"},
	},
	KindInvitation: {
		LocaleVI: {"[MeshGuard] Lời mời tham gia tenant {{.tenant_name}}",
			"Bạn được mời tham gia tenant {{.tenant_name}} ({{.tenant_slug}}) với vai trò {{.role}}.\n\n" +
				"Đăng nhập bằng nhà cung cấp danh tính của tenant tại {{.portal_url}} bằng đúng địa chỉ email này (đã xác minh) " +
				"trước {{.expires_at}} (UTC) để nhận lời mời.\n\nNếu bạn không mong đợi lời mời này, hãy bỏ qua email."},
		LocaleEN: {"[MeshGuard] Invitation to tenant {{.tenant_name}}",
			"You have been invited to tenant {{.tenant_name}} ({{.tenant_slug}}) with the role {{.role}}.\n\n" +
				"Sign in with the tenant's identity provider at {{.portal_url}} using this verified e-mail address " +
				"before {{.expires_at}} (UTC) to accept it.\n\nIf you did not expect this invitation, ignore this e-mail."},
	},
	KindTenantSuspended: {
		LocaleVI: {"[MeshGuard] Tenant {{.tenant_name}} bị tạm ngưng",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) đã bị tạm ngưng: thiết bị không còn kết nối được với nhau và thao tác ghi bị từ chối cho tới khi tenant được khôi phục.\n\nMã job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] Tenant {{.tenant_name}} suspended",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) has been suspended: devices can no longer reach each other and changes are refused until the tenant is resumed.\n\nJob ID: {{.job_id}}"},
	},
	KindInstanceRestored: {
		LocaleVI: {"[MeshGuard] Control plane của tenant {{.tenant_name}} đã được khôi phục từ backup",
			"Control plane (Headscale) của tenant {{.tenant_name}} ({{.tenant_slug}}) đã được khôi phục từ bản backup lấy lúc {{.backup_created_at}} (UTC). " +
				"Mọi API key và pre-auth key có trong bản backup đã bị vô hiệu; thiết bị đăng ký sau thời điểm đó phải enroll lại." +
				"{{if eq .owner_review \"required\"}}\n\nCẦN RÀ SOÁT: sổ của nền tảng cũ hơn bản backup, nên các thu hồi (thiết bị, thành viên) thực hiện sau thời điểm backup không khôi phục được. Hãy rà lại danh sách thiết bị và thành viên trong Portal; policy trong bản backup được giữ và chờ bạn duyệt lại.{{end}}" +
				"\n\nMã job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] The control plane of tenant {{.tenant_name}} was restored from a backup",
			"The control plane (Headscale) of tenant {{.tenant_name}} ({{.tenant_slug}}) was restored from the backup taken at {{.backup_created_at}} (UTC). " +
				"Every API key and pre-auth key in that backup has been invalidated; devices registered after that time must enroll again." +
				"{{if eq .owner_review \"required\"}}\n\nREVIEW REQUIRED: the platform's records are older than the backup, so revocations (devices, members) made after the backup's time could not be restored. Review the devices and members in the Portal; the policy of the backup was kept and awaits your approval.{{end}}" +
				"\n\nJob ID: {{.job_id}}"},
	},
	KindTenantDeleted: {
		LocaleVI: {"[MeshGuard] Tenant {{.tenant_name}} đã bị xóa",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) đã bị xóa theo yêu cầu đã được hai người phê duyệt: mọi thiết bị đã hết hạn, " +
				"phiên đăng nhập Portal đã bị thu hồi và control plane đã được gỡ khỏi máy chủ." +
				"{{if eq .final_backup \"kept\"}} Bản backup cuối được giữ tới {{.keys_destroy_after}} (UTC).{{else}} Không có bản backup cuối (người vận hành đã bỏ qua có ghi audit).{{end}}" +
				" Từ {{.keys_destroy_after}} (UTC), khóa mã hóa của tenant bị hủy và không còn khôi phục được gì.\n\nMã job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] Tenant {{.tenant_name}} has been deleted",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) has been deleted on a request approved by two people: every device has expired, " +
				"Portal sessions have been revoked and the control plane has been removed from the server." +
				"{{if eq .final_backup \"kept\"}} The final backup is kept until {{.keys_destroy_after}} (UTC).{{else}} There is no final backup (an operator skipped it; this is audited).{{end}}" +
				" From {{.keys_destroy_after}} (UTC) the tenant's encryption keys are destroyed and nothing can be restored.\n\nJob ID: {{.job_id}}"},
	},
	KindInstanceOpFailed: {
		LocaleVI: {"[MeshGuard] Thao tác {{.operation}} trên instance {{.tenant_slug}} thất bại",
			"Job {{.operation}} trên instance Headscale của tenant {{.tenant_slug}} thất bại (mã {{.code}}); kết quả: {{.outcome}} " +
				"(rolled_back: đã trở về trạng thái trước; rollback_failed: tự lùi cũng lỗi — cần xử lý ngay, /rollback để chạy tiếp; " +
				"resumable: hết lượt thử lại, khóa vòng đời của tenant còn giữ tới /retry hoặc /rollback). " +
				"Xem job trong Platform Console: {{.console_url}}\n\nMã job: {{.job_id}}\nMã instance: {{.instance_id}}"},
		LocaleEN: {"[MeshGuard] {{.operation}} of instance {{.tenant_slug}} failed",
			"The {{.operation}} job of the Headscale instance of tenant {{.tenant_slug}} failed (code {{.code}}); outcome: {{.outcome}} " +
				"(rolled_back: the previous state is back; rollback_failed: the automatic rollback failed too — act now, /rollback resumes it; " +
				"resumable: the retries are spent, the tenant's lifecycle lock is held until /retry or /rollback). " +
				"See the job in the Platform Console: {{.console_url}}\n\nJob ID: {{.job_id}}\nInstance ID: {{.instance_id}}"},
	},
	KindTenantResumed: {
		LocaleVI: {"[MeshGuard] Tenant {{.tenant_name}} đã được khôi phục",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) đã hoạt động lại; policy trước khi tạm ngưng được áp lại.\n\nMã job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] Tenant {{.tenant_name}} resumed",
			"Tenant {{.tenant_name}} ({{.tenant_slug}}) is active again; the policy in force before the suspension is applied again.\n\nJob ID: {{.job_id}}"},
	},
	KindDeviceNew: {
		LocaleVI: {"[MeshGuard] Thiết bị mới trong tenant {{.tenant_name}}: {{.device_name}}",
			"Thiết bị {{.device_name}} vừa tham gia mạng của tenant {{.tenant_name}}{{with .registered_at}} lúc {{.}} (UTC){{end}}.\n\n" +
				"Nếu bạn không thêm thiết bị này, hãy thu hồi ngay trong Portal và báo cho quản trị viên của tenant.\n\nMã thiết bị: {{.device_id}}"},
		LocaleEN: {"[MeshGuard] New device in tenant {{.tenant_name}}: {{.device_name}}",
			"Device {{.device_name}} has joined the network of tenant {{.tenant_name}}{{with .registered_at}} at {{.}} (UTC){{end}}.\n\n" +
				"If you did not add this device, revoke it in the Portal now and tell the tenant's administrators.\n\nDevice ID: {{.device_id}}"},
	},
	KindDeviceExpiring: {
		LocaleVI: {"[MeshGuard] Thiết bị {{.device_name}} sắp hết hạn",
			"Khóa của thiết bị {{.device_name}} trong tenant {{.tenant_name}} hết hạn lúc {{.expires_at}} (UTC). Sau thời điểm đó thiết bị mất kết nối cho tới khi được đăng nhập lại.\n\nMã thiết bị: {{.device_id}}"},
		LocaleEN: {"[MeshGuard] Device {{.device_name}} expires soon",
			"The key of device {{.device_name}} in tenant {{.tenant_name}} expires at {{.expires_at}} (UTC). After that the device is disconnected until it signs in again.\n\nDevice ID: {{.device_id}}"},
	},
	KindAPIKeyExpiring: {
		LocaleVI: {"[MeshGuard] API key của instance {{.tenant_slug}} sắp hết hạn",
			"API key của instance Headscale thuộc tenant {{.tenant_slug}} hết hạn lúc {{.expires_at}} (UTC) mà chưa được xoay. Kiểm tra job apikey.rotate trong Platform Console: {{.console_url}}\n\nMã instance: {{.instance_id}}"},
		LocaleEN: {"[MeshGuard] API key of instance {{.tenant_slug}} expires soon",
			"The API key of the Headscale instance of tenant {{.tenant_slug}} expires at {{.expires_at}} (UTC) and has not been rotated. Check the apikey.rotate job in the Platform Console: {{.console_url}}\n\nInstance ID: {{.instance_id}}"},
	},
	KindPolicyApplied: {
		LocaleVI: {"[MeshGuard] Policy v{{.version}} đã áp dụng cho tenant {{.tenant_name}}",
			"Policy version {{.version}} ({{.policy_kind}}, kích hoạt: {{.trigger}}) đã được áp dụng lên control plane của tenant {{.tenant_name}} và đọc lại khớp (sha256 {{.applied_sha256}}).\n\n" +
				"Thiết bị nhận policy mới khi kết nối với control plane; thiết bị đang ngoại tuyến cập nhật khi kết nối lại."},
		LocaleEN: {"[MeshGuard] Policy v{{.version}} applied to tenant {{.tenant_name}}",
			"Policy version {{.version}} ({{.policy_kind}}, trigger: {{.trigger}}) has been applied to the control plane of tenant {{.tenant_name}} and read back identical (sha256 {{.applied_sha256}}).\n\n" +
				"Devices receive the new policy while connected to the control plane; offline devices update when they reconnect."},
	},
	KindSupportGrantRequested: {
		LocaleVI: {"[MeshGuard] Yêu cầu quyền hỗ trợ vào tenant {{.tenant_name}}",
			"Nhân sự nền tảng {{.staff}} yêu cầu quyền hỗ trợ có thời hạn vào tenant {{.tenant_name}}{{with .reason}}. Lý do: {{.}}{{end}}.\n\n" +
				"Duyệt hoặc từ chối trong Portal (mục Support grants). Mã yêu cầu: {{.grant_id}}"},
		LocaleEN: {"[MeshGuard] Support access requested for tenant {{.tenant_name}}",
			"Platform staff member {{.staff}} requests time-limited support access to tenant {{.tenant_name}}{{with .reason}}. Reason: {{.}}{{end}}.\n\n" +
				"Approve or reject it in the Portal (Support grants). Request ID: {{.grant_id}}"},
	},
	KindBreakGlass: {
		LocaleVI: {"[MeshGuard] CẢNH BÁO: truy cập khẩn cấp (break-glass) vào tenant {{.tenant_name}}",
			"Nhân sự nền tảng {{.staff}} được cấp quyền hỗ trợ vào tenant {{.tenant_name}} theo thủ tục khẩn cấp (break-glass){{with .approver}}, do {{.}} phê duyệt{{end}}{{with .reason}}. Lý do: {{.}}{{end}}{{with .expires_at}}. Quyền hết hạn lúc {{.}} (UTC){{end}}.\n\n" +
				"Mọi thao tác của họ được ghi audit. Xem và thu hồi trong Portal. Mã grant: {{.grant_id}}"},
		LocaleEN: {"[MeshGuard] ALERT: break-glass access to tenant {{.tenant_name}}",
			"Platform staff member {{.staff}} was granted support access to tenant {{.tenant_name}} through the break-glass procedure{{with .approver}}, approved by {{.}}{{end}}{{with .reason}}. Reason: {{.}}{{end}}{{with .expires_at}}. The access expires at {{.}} (UTC){{end}}.\n\n" +
				"Every action is audited. Review and revoke it in the Portal. Grant ID: {{.grant_id}}"},
	},
	KindSupportGrantUsed: {
		LocaleVI: {"[MeshGuard] Quyền hỗ trợ vào tenant {{.tenant_name}} đã được sử dụng",
			"Nhân sự nền tảng {{.staff}} đã thao tác trong tenant {{.tenant_name}} bằng quyền hỗ trợ (lần đầu lúc {{.first_used_at}} UTC). Xem nhật ký audit trong Portal.\n\nMã grant: {{.grant_id}}"},
		LocaleEN: {"[MeshGuard] Support access to tenant {{.tenant_name}} was used",
			"Platform staff member {{.staff}} acted inside tenant {{.tenant_name}} with a support grant (first at {{.first_used_at}} UTC). See the audit log in the Portal.\n\nGrant ID: {{.grant_id}}"},
	},
	KindApprovalRequested: {
		LocaleVI: {"[MeshGuard] Yêu cầu phê duyệt trong tenant {{.tenant_name}}: {{.action}}",
			"Một thao tác cần người thứ hai phê duyệt trong tenant {{.tenant_name}}: {{.action}}{{with .requested_by}} (người yêu cầu: {{.}}){{end}}{{with .expires_at}}. Yêu cầu hết hạn lúc {{.}} (UTC){{end}}.\n\n" +
				"Xem nội dung và quyết định trong Portal (mục Phê duyệt). Mã yêu cầu: {{.approval_id}}"},
		LocaleEN: {"[MeshGuard] Approval requested in tenant {{.tenant_name}}: {{.action}}",
			"An operation needs a second approver in tenant {{.tenant_name}}: {{.action}}{{with .requested_by}} (requested by {{.}}){{end}}{{with .expires_at}}. The request expires at {{.}} (UTC){{end}}.\n\n" +
				"Review it and decide in the Portal (Approvals). Request ID: {{.approval_id}}"},
	},
	KindIdPAdminChange: {
		LocaleVI: {"[MeshGuard] CẢNH BÁO: thay đổi quản trị tại nhà cung cấp danh tính của tenant {{.tenant_name}}",
			"Một thao tác quản trị đã được thực hiện trực tiếp tại nhà cung cấp danh tính (Keycloak) của tenant {{.tenant_name}}: {{.action}}{{with .user}}, người dùng: {{.}}{{end}}. Người thực hiện: {{.actor}}, lúc {{.occurred_at}} (UTC).\n\n" +
				"Thao tác này không đi qua Portal của bạn. Xem chi tiết trong nhật ký audit của tenant; nếu bạn không mong đợi thay đổi này, hãy liên hệ nhà vận hành nền tảng ngay.\n\nMã sự kiện: {{.event_id}}"},
		LocaleEN: {"[MeshGuard] ALERT: administrative change at the identity provider of tenant {{.tenant_name}}",
			"An administrative operation was performed directly at the identity provider (Keycloak) of tenant {{.tenant_name}}: {{.action}}{{with .user}}, user: {{.}}{{end}}. Performed by: {{.actor}}, at {{.occurred_at}} (UTC).\n\n" +
				"This operation did not go through your Portal. See the tenant's audit log for details; if you did not expect this change, contact the platform operator at once.\n\nEvent ID: {{.event_id}}"},
	},
	KindIdPConfigChanged: {
		LocaleVI: {"[MeshGuard] Thay đổi cấu hình nhà cung cấp danh tính của tenant {{.tenant_name}}",
			"Cấu hình nhà cung cấp danh tính (IdP) của tenant {{.tenant_name}} — trường: {{.changed}} — {{if eq .stage \"requested\"}}đang CHỜ PHÊ DUYỆT, chưa có hiệu lực{{else}}đã có hiệu lực{{end}}. " +
				"Nguồn: {{if eq .origin \"platform\"}}nhân sự nền tảng (cần hai Super Admin duyệt){{else}}Tenant Owner trong Portal{{end}}{{with .actor}}, người thực hiện: {{.}}{{end}}.\n\n" +
				"Xem nhật ký audit của tenant; nếu bạn không mong đợi thay đổi này, hãy liên hệ nhà vận hành nền tảng ngay.{{with .approval_id}}\n\nMã yêu cầu: {{.}}{{end}}"},
		LocaleEN: {"[MeshGuard] Identity provider configuration change for tenant {{.tenant_name}}",
			"The identity provider (IdP) configuration of tenant {{.tenant_name}} — fields: {{.changed}} — {{if eq .stage \"requested\"}}is AWAITING APPROVAL and not in effect yet{{else}}is now in effect{{end}}. " +
				"Origin: {{if eq .origin \"platform\"}}platform staff (two Super Admins must approve){{else}}a Tenant Owner in the Portal{{end}}{{with .actor}}, by: {{.}}{{end}}.\n\n" +
				"See the tenant's audit log; if you did not expect this change, contact the platform operator at once.{{with .approval_id}}\n\nRequest ID: {{.}}{{end}}"},
	},
	KindSecuritySettingsChanged: {
		LocaleVI: {"[MeshGuard] Thiết lập bảo mật của tenant {{.tenant_name}} đã thay đổi",
			"Thiết lập bảo mật của tenant {{.tenant_name}} vừa được ghi — khóa đổi: {{.changed}}{{with .actor}}, người thực hiện: {{.}}{{end}}{{with .approval_id}} (theo yêu cầu phê duyệt {{.}}){{end}}.\n\n" +
				"Xem chi tiết trong nhật ký audit của tenant."},
		LocaleEN: {"[MeshGuard] Security settings of tenant {{.tenant_name}} changed",
			"The security settings of tenant {{.tenant_name}} were written — keys changed: {{.changed}}{{with .actor}}, by: {{.}}{{end}}{{with .approval_id}} (approval request {{.}}){{end}}.\n\n" +
				"See the tenant's audit log for details."},
	},
	KindTenantDeletionRequested: {
		LocaleVI: {"[MeshGuard] Đã gửi yêu cầu xóa tenant {{.tenant_name}}",
			"Một Tenant Owner{{with .requested_by}} ({{.}}){{end}} đã yêu cầu nền tảng xóa tenant {{.tenant_name}} lúc {{.requested_at}} (UTC). " +
				"Chưa có gì bị xóa: nhân sự nền tảng liên hệ trước khi xóa (thao tác cần hai người duyệt).\n\nNếu bạn không mong đợi yêu cầu này, hãy liên hệ nhà vận hành nền tảng ngay."},
		LocaleEN: {"[MeshGuard] Deletion of tenant {{.tenant_name}} requested",
			"A Tenant Owner{{with .requested_by}} ({{.}}){{end}} asked the platform to delete tenant {{.tenant_name}} at {{.requested_at}} (UTC). " +
				"Nothing has been deleted: platform staff get in touch before deleting it (the deletion needs two approvers).\n\nIf you did not expect this request, contact the platform operator at once."},
	},
	KindPlatformTenantDeletionRequest: {
		LocaleVI: {"[MeshGuard] Tenant {{.tenant_slug}} yêu cầu xóa tenant",
			"Tenant Owner{{with .requested_by}} {{.}}{{end}} của tenant {{.tenant_slug}} đã yêu cầu xóa tenant lúc {{.requested_at}} (UTC). " +
				"Xem lý do trong audit nền tảng; xác minh với tenant rồi xóa bằng thao tác xóa tenant (2P) trong Platform Console: {{.console_url}}\n\nMã tenant: {{.tenant_id}}"},
		LocaleEN: {"[MeshGuard] Tenant {{.tenant_slug}} requested its deletion",
			"Tenant Owner{{with .requested_by}} {{.}}{{end}} of tenant {{.tenant_slug}} asked for the tenant's deletion at {{.requested_at}} (UTC). " +
				"See the reason in the platform audit; verify with the tenant, then delete it with the tenant deletion (2P) in the Platform Console: {{.console_url}}\n\nTenant ID: {{.tenant_id}}"},
	},
	KindIdPConsoleLogin: { // one sign-in, or ({{if .count}}) the summary of the sign-ins held back in a window (F-G3-2)
		LocaleVI: {"[MeshGuard] CẢNH BÁO: {{if .count}}{{.count}} lần đăng nhập quản trị Keycloak nữa{{with .username}} ({{.}}){{end}}{{else}}đăng nhập quản trị Keycloak ({{.client}}){{end}}",
			"{{if .count}}Trong cửa sổ {{.window_minutes}} phút sau lần đăng nhập đã được báo riêng (cùng tài khoản, client và địa chỉ), có thêm {{.count}} lần đăng nhập vào khu quản trị của Keycloak do nền tảng host{{with .username}} bằng tài khoản {{.}}{{end}}, từ {{.first_at}} đến {{.occurred_at}} (UTC){{with .sources}}; nguồn: {{.}}{{end}}.\n\n" +
				"Các lần này được gộp vào một thư; mỗi lần vẫn là một security event idp.console_login riêng. {{else}}Có một lần đăng nhập vào khu quản trị của Keycloak do nền tảng host: client {{.client}}{{with .username}}, tài khoản {{.}}{{end}}{{with .ip}}, từ {{.}}{{end}}, lúc {{.occurred_at}} (UTC).\n\n{{end}}" +
				"Mỗi lần đăng nhập console cần một phiên đã được hai Super Admin duyệt; nếu không có phiên nào như vậy, hãy xử lý như sự cố bảo mật. Xem security event trong Platform Console: {{.console_url}}\n\n{{if .count}}Mã sự kiện cuối: {{else}}Mã sự kiện: {{end}}{{.event_id}}"},
		LocaleEN: {"[MeshGuard] ALERT: {{if .count}}{{.count}} more Keycloak administration sign-ins{{with .username}} ({{.}}){{end}}{{else}}Keycloak administration sign-in ({{.client}}){{end}}",
			"{{if .count}}In the {{.window_minutes}}-minute window after the sign-in notified on its own (same account, client and address), there were {{.count}} more sign-ins to the administration of the platform-hosted Keycloak{{with .username}} with account {{.}}{{end}}, from {{.first_at}} to {{.occurred_at}} (UTC){{with .sources}}; sources: {{.}}{{end}}.\n\n" +
				"They are grouped in one e-mail; each one is still its own security event idp.console_login. {{else}}Someone signed in to the administration of the platform-hosted Keycloak: client {{.client}}{{with .username}}, account {{.}}{{end}}{{with .ip}}, from {{.}}{{end}}, at {{.occurred_at}} (UTC).\n\n{{end}}" +
				"Every console sign-in needs a session approved by two Super Admins; if there is no such session, handle it as a security incident. See the security events in the Platform Console: {{.console_url}}\n\n{{if .count}}Last event ID: {{else}}Event ID: {{end}}{{.event_id}}"},
	},
	KindInstanceQuarantined: {
		LocaleVI: {"[MeshGuard] CẢNH BÁO: instance {{.tenant_slug}} bị quarantine ({{.outcome}})",
			"Instance Headscale của tenant {{.tenant_slug}} đã bị quarantine (§11.4): hostname của tenant trả 404, container dừng, dữ liệu giữ nguyên để điều tra. Kết quả của job: {{.outcome}}" +
				"{{if eq .outcome \"incomplete\"}} — instance CÓ THỂ VẪN PHỤC VỤ: cô lập bằng tay theo RUNBOOK ngay{{end}}.\n\n" +
				"Chỉ gỡ được bằng release có người thứ hai duyệt. Xem job và security event trong Platform Console: {{.console_url}}\n\nMã instance: {{.instance_id}} · job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] ALERT: instance {{.tenant_slug}} quarantined ({{.outcome}})",
			"The Headscale instance of tenant {{.tenant_slug}} was quarantined (§11.4): the tenant's hostname answers 404, the container is stopped, its data is kept for the investigation. Job outcome: {{.outcome}}" +
				"{{if eq .outcome \"incomplete\"}} — the instance MAY STILL SERVE: isolate it by hand following the RUNBOOK now{{end}}.\n\n" +
				"Only a release approved by a second person lifts it. See the job and the security events in the Platform Console: {{.console_url}}\n\nInstance ID: {{.instance_id}} · job: {{.job_id}}"},
	},
	KindEnrollmentApproved: {
		LocaleVI: {"[MeshGuard] Yêu cầu thêm thiết bị trong tenant {{.tenant_name}} đã được duyệt",
			"Yêu cầu thêm thiết bị{{with .device_label}} {{.}}{{end}} của bạn trong tenant {{.tenant_name}} (phương thức {{.method}}) đã được duyệt{{with .decided_by}} bởi {{.}}{{end}}.\n\n" +
				"Đăng nhập Portal và bấm \"Bắt đầu\" ở yêu cầu này trước {{.expires_at}} (UTC) để nhận mã hoặc key — sau thời điểm đó yêu cầu hết hạn. Mã/key chỉ hiển thị trong Portal, không bao giờ gửi qua email.\n\nMã yêu cầu: {{.request_id}}"},
		LocaleEN: {"[MeshGuard] Your device request in tenant {{.tenant_name}} was approved",
			"Your request to add a device{{with .device_label}} {{.}}{{end}} in tenant {{.tenant_name}} (method {{.method}}) was approved{{with .decided_by}} by {{.}}{{end}}.\n\n" +
				"Sign in to the Portal and choose \"Start\" on this request before {{.expires_at}} (UTC) to receive the code or key — the request expires after that. Codes and keys are shown in the Portal only, never sent by e-mail.\n\nRequest ID: {{.request_id}}"},
	},
	KindEnrollmentRejected: {
		LocaleVI: {"[MeshGuard] Yêu cầu thêm thiết bị trong tenant {{.tenant_name}} bị từ chối",
			"Yêu cầu thêm thiết bị{{with .device_label}} {{.}}{{end}} của bạn trong tenant {{.tenant_name}} (phương thức {{.method}}) đã bị từ chối{{with .decided_by}} bởi {{.}}{{end}}. Không có mã hay key nào được phát.\n\n" +
				"Nếu bạn vẫn cần thêm thiết bị, hãy liên hệ quản trị viên của tenant.\n\nMã yêu cầu: {{.request_id}}"},
		LocaleEN: {"[MeshGuard] Your device request in tenant {{.tenant_name}} was rejected",
			"Your request to add a device{{with .device_label}} {{.}}{{end}} in tenant {{.tenant_name}} (method {{.method}}) was rejected{{with .decided_by}} by {{.}}{{end}}. No code or key was issued.\n\n" +
				"If you still need the device, contact the tenant's administrators.\n\nRequest ID: {{.request_id}}"},
	},
	KindRouteApproved: {
		LocaleVI: {"[MeshGuard] {{if .exit_node}}Exit node{{else}}Route{{end}} được duyệt trên thiết bị {{.device_name}} (tenant {{.tenant_name}})",
			"Đã duyệt trên thiết bị {{.device_name}} của tenant {{.tenant_name}}: {{.prefixes}}{{with .actor}}, người thực hiện: {{.}}{{end}}{{with .approval_id}} (thực thi yêu cầu phê duyệt {{.}} — người thứ hai đã duyệt){{end}}." +
				"{{if .exit_node}}\n\nThiết bị này giờ là exit node: lưu lượng Internet của các client chọn nó đi qua thiết bị.{{end}}" +
				"{{if .untagged_router}}\n\nCảnh báo: thiết bị không phải tagged node (router thuộc một người dùng) — quy ước là chỉ duyệt route cho router gắn tag.{{end}}" +
				"\n\nNếu bạn không mong đợi thay đổi này, hãy gỡ duyệt trong Portal (mục Routes) và xem nhật ký audit.\n\nMã thiết bị: {{.device_id}}"},
		LocaleEN: {"[MeshGuard] {{if .exit_node}}Exit node{{else}}Routes{{end}} approved on device {{.device_name}} (tenant {{.tenant_name}})",
			"Approved on device {{.device_name}} of tenant {{.tenant_name}}: {{.prefixes}}{{with .actor}}, by: {{.}}{{end}}{{with .approval_id}} (execution of approval request {{.}} — a second person approved it){{end}}." +
				"{{if .exit_node}}\n\nThis device is now an exit node: the Internet traffic of the clients that select it goes through the device.{{end}}" +
				"{{if .untagged_router}}\n\nWarning: the device is not a tagged node (the router belongs to a user) — by convention only tagged routers get routes approved.{{end}}" +
				"\n\nIf you did not expect this change, revoke it in the Portal (Routes) and check the audit log.\n\nDevice ID: {{.device_id}}"},
	},
	KindRouteRevoked: {
		LocaleVI: {"[MeshGuard] {{if .exit_node}}Exit node{{else}}Route{{end}} bị gỡ duyệt trên thiết bị {{.device_name}} (tenant {{.tenant_name}})",
			"Đã gỡ duyệt trên thiết bị {{.device_name}} của tenant {{.tenant_name}}: {{.prefixes}}{{with .actor}}, người thực hiện: {{.}}{{end}}. Client không còn đi qua thiết bị cho các prefix này.\n\n" +
				"Xem nhật ký audit trong Portal.\n\nMã thiết bị: {{.device_id}}"},
		LocaleEN: {"[MeshGuard] {{if .exit_node}}Exit node{{else}}Routes{{end}} revoked on device {{.device_name}} (tenant {{.tenant_name}})",
			"Revoked on device {{.device_name}} of tenant {{.tenant_name}}: {{.prefixes}}{{with .actor}}, by: {{.}}{{end}}. Clients no longer route these prefixes through the device.\n\n" +
				"See the audit log in the Portal.\n\nDevice ID: {{.device_id}}"},
	},
	KindInstanceReleased: {
		LocaleVI: {"[MeshGuard] Release instance {{.tenant_slug}}: {{.outcome}}",
			"Release (đã được người thứ hai duyệt) của instance Headscale thuộc tenant {{.tenant_slug}} kết thúc: {{.outcome}}" +
				"{{if eq .outcome \"released\"}} — instance đã qua start guard và post-start gate, phục vụ lại{{else}} — instance vẫn bị quarantine{{end}}.\n\n" +
				"Xem job trong Platform Console: {{.console_url}}\n\nMã instance: {{.instance_id}} · job: {{.job_id}}"},
		LocaleEN: {"[MeshGuard] Release of instance {{.tenant_slug}}: {{.outcome}}",
			"The release (approved by a second person) of the Headscale instance of tenant {{.tenant_slug}} ended: {{.outcome}}" +
				"{{if eq .outcome \"released\"}} — the instance passed the start guard and the post-start gate and serves again{{else}} — the instance stays quarantined{{end}}.\n\n" +
				"See the job in the Platform Console: {{.console_url}}\n\nInstance ID: {{.instance_id}} · job: {{.job_id}}"},
	},
}

// templates are the parsed catalog.
type templates struct {
	subject map[Kind]map[string]*template.Template
	body    map[Kind]map[string]*template.Template
}

// parseTemplates parses the catalog; every kind must have both locales (TestCatalogCoversEveryKind).
func parseTemplates() (*templates, error) {
	t := &templates{subject: map[Kind]map[string]*template.Template{}, body: map[Kind]map[string]*template.Template{}}
	for kind, locales := range catalog {
		t.subject[kind], t.body[kind] = map[string]*template.Template{}, map[string]*template.Template{}
		for loc, mt := range locales {
			s, err := template.New(string(kind) + "." + loc + ".subject").Option("missingkey=error").Parse(mt.subject)
			if err != nil {
				return nil, fmt.Errorf("notifications: template %s/%s subject: %w", kind, loc, err)
			}
			b, err := template.New(string(kind) + "." + loc + ".body").Option("missingkey=error").Parse(mt.body + footers[loc])
			if err != nil {
				return nil, fmt.Errorf("notifications: template %s/%s body: %w", kind, loc, err)
			}
			t.subject[kind][loc], t.body[kind][loc] = s, b
		}
	}
	return t, nil
}

// render returns the subject (one line) and body of a notification. data is the stored payload plus the links.
func (t *templates) render(kind Kind, locale string, data map[string]any) (subject, body string, err error) {
	if _, ok := t.subject[kind][locale]; !ok {
		locale = DefaultLocale
	}
	st, bt := t.subject[kind][locale], t.body[kind][locale]
	if st == nil || bt == nil {
		return "", "", fmt.Errorf("notifications: no template for %s", kind)
	}
	// Optional fields absent from the payload render as empty ({{with}}); declare them so missingkey=error only
	// catches fields that are really required.
	full := make(map[string]any, len(data)+8)
	for k := range specs[kind].fields {
		full[k] = ""
	}
	for k, v := range data {
		full[k] = v
	}
	var sb, bb bytes.Buffer
	if err := st.Execute(&sb, full); err != nil {
		return "", "", fmt.Errorf("notifications: render %s subject: %w", kind, err)
	}
	if err := bt.Execute(&bb, full); err != nil {
		return "", "", fmt.Errorf("notifications: render %s body: %w", kind, err)
	}
	subject = strings.Join(strings.Fields(sb.String()), " ") // one header line, whatever a value holds
	return subject, bb.String(), nil
}
