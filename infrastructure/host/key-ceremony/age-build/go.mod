// P3-T11a — module bọc để build age/age-keygen (versions.lock [sources.age]) với phụ thuộc đã vá. Dùng chung bởi
// infrastructure/host/key-ceremony/build-age.sh (nghi thức khóa, tests/backup/drill.sh) và stage age của
// infrastructure/docker/backup/Dockerfile + infrastructure/docker/agent/Dockerfile. Không có mã Go: chỉ chỉ thị
// tool + require; build bằng `go build -mod=readonly filippo.io/age/cmd/age …` (go.sum pin mọi module).
// Lý do: `go install filippo.io/age/cmd/age@v1.3.2` không ghi đè được phụ thuộc — v1.3.2 khai báo
// golang.org/x/crypto v0.55.0 (grype: GO-2026-6354, GO-2026-6355, DoS kênh x/crypto/ssh; bản sửa v0.56.0).
// Đổi phiên bản nào ở đây ⇒ sha256 của binary đổi ⇒ cập nhật versions.lock [sources.age] và AGE_SHA256 của hai Dockerfile.
module github.com/zhaduchanhzz/network-access-mesh/infrastructure/host/key-ceremony/age-build

go 1.27.4

tool (
	filippo.io/age/cmd/age
	filippo.io/age/cmd/age-keygen
)

require (
	filippo.io/age v1.3.2 // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	filippo.io/hpke v0.4.0 // indirect
	filippo.io/nistec v0.0.4 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
)
