// Package agentv1 is the generated Go code of agent.proto — the protocol between the worker and the Host Agent
// (P3-T01; master plan §11.1, §11.5). agent.pb.go and agent_grpc.pb.go are generated: edit agent.proto, then run
// `make agent-gen` (go generate ./api/agent/v1) and commit the result; CI regenerates and fails on any difference.
//
// buf (pinned, run through the Go checksum database) lints the file and drives the two local plugins of
// api/buf.gen.yaml. Every request type is closed: the validation that gives the types their meaning (UUIDs, digest
// allowlist, ranges, ownership labels) lives in internal/provisioning/agentspec and runs in the agent.
package agentv1

//go:generate go run github.com/bufbuild/buf/cmd/buf@v1.75.0 lint ../..
//go:generate go run github.com/bufbuild/buf/cmd/buf@v1.75.0 generate ../.. --template ../../buf.gen.yaml -o ../..
