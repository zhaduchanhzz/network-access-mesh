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
	KindIdPConsoleLogin: {
		LocaleVI: {"[MeshGuard] CẢNH BÁO: đăng nhập quản trị Keycloak ({{.client}})",
			"Có một lần đăng nhập vào khu quản trị của Keycloak do nền tảng host: client {{.client}}{{with .username}}, tài khoản {{.}}{{end}}{{with .ip}}, từ {{.}}{{end}}, lúc {{.occurred_at}} (UTC).\n\n" +
				"Mỗi lần đăng nhập console cần một phiên đã được hai Super Admin duyệt; nếu không có phiên nào như vậy, hãy xử lý như sự cố bảo mật. Xem security event trong Platform Console: {{.console_url}}\n\nMã sự kiện: {{.event_id}}"},
		LocaleEN: {"[MeshGuard] ALERT: Keycloak administration sign-in ({{.client}})",
			"Someone signed in to the administration of the platform-hosted Keycloak: client {{.client}}{{with .username}}, account {{.}}{{end}}{{with .ip}}, from {{.}}{{end}}, at {{.occurred_at}} (UTC).\n\n" +
				"Every console sign-in needs a session approved by two Super Admins; if there is no such session, handle it as a security incident. See the security events in the Platform Console: {{.console_url}}\n\nEvent ID: {{.event_id}}"},
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
