// Package gen holds the strict server interface (net/http ServeMux) and the models generated from api/openapi.yaml by
// oapi-codegen (§4.3, §13.1). api.gen.go is generated — never edit it: change the spec, then run
// `go generate ./internal/httpapi/gen` (or `make api-gen`). CI regenerates it and fails when the committed file
// differs from the spec (P2-T02). Handlers implement StrictServerInterface in the tasks that own each operation
// (x-task in the spec); the middleware chain maps the operation to its x-permission (P2-T07).
package gen

//go:generate go tool oapi-codegen -config config.yaml ../../../api/openapi.yaml
