package compose

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/zhaduchanhzz/network-access-mesh/internal/provisioning/agentspec"
)

// Throw-away helper containers (§11.5): the agent (root) never reads or parses a file a tenant process can write. What
// it needs from data/ — the Noise key fingerprint — is computed by a one-shot container running as the tenant's
// run_uid, without network, capability or writable rootfs, with data/ mounted read-only and a hard timeout. The
// syntax gate of a configuration (`headscale configtest`, which creates keys and opens/migrates a database — RT-05)
// runs the same way with a scratch data directory on tmpfs.

// Labels of helper containers. They never carry meshguard.instance_id (the guard would see a second container of the
// instance — P3-T01 note): the instance they serve is meshguard.helper_instance_id.
const (
	LabelHelper           = "meshguard.helper"
	LabelHelperInstanceID = "meshguard.helper_instance_id"
	RoleAgentHelper       = "agent-helper"
)

// Helper operations (the label value and part of the container name).
const (
	helperConfigtest  = "configtest"
	helperFingerprint = "fingerprint"
)

const (
	// NoiseKeyPath is where Headscale reads its Noise private key (config.yaml noise.private_key_path) and where the
	// fingerprint helper finds it (data/ mounted read-only at /var/lib/headscale).
	NoiseKeyPath = "/var/lib/headscale/noise_private.key"
	// HelperBinary is the agent binary inside the agent image (the image of the fingerprint helper).
	HelperBinary = "/usr/local/bin/meshguard-agent"
	// FingerprintCommand is the agent's subcommand run by the fingerprint helper.
	FingerprintCommand = "noise-fingerprint"
	// Exit codes of the fingerprint helper: the key file is absent / not a valid key (definitive start-guard
	// violations); any other non-zero code is an error (indeterminate — fail closed, retried).
	FingerprintExitAbsent  = 3
	FingerprintExitInvalid = 4

	fingerprintTimeout = 20 * time.Second
	configtestTimeout  = 60 * time.Second
	helperMaxOutput    = 64 << 10
)

// helperName is the name of one helper run: mg-helper-<slug>-<op>-<8 hex>. The slug keeps the helpers of a test run
// identifiable for its cleanup; the random part keeps two runs apart.
func helperName(slug, op string) (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "mg-helper-" + slug + "-" + op + "-" + hex.EncodeToString(b[:]), nil
}

func helperLabels(ref agentspec.Ref, op string) map[string]string {
	return map[string]string{agentspec.LabelRole: RoleAgentHelper, LabelHelper: op, LabelHelperInstanceID: ref.InstanceID.String()}
}

// ---------------------------------------------------------------------------------------------------- Noise key

// Sizes of noise_private.key: "privkey:" + 64 hex (72 bytes, written by Headscale without a newline); a trailing
// newline or two is tolerated (Headscale trims whitespace when it reads the file).
const (
	noiseKeyMinBytes = 72
	noiseKeyMaxBytes = 80
)

var (
	noiseKeyRE    = regexp.MustCompile(`^privkey:([0-9a-f]{64})$`)
	fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrNoiseKeyAbsent / ErrNoiseKeyInvalid are the definitive outcomes of FingerprintNoiseKeyFile.
var (
	ErrNoiseKeyAbsent  = errors.New("noise_private.key does not exist")
	ErrNoiseKeyInvalid = errors.New("noise_private.key is not a regular file holding a Noise private key")
)

// NoiseFingerprint is the fingerprint the agent records and compares (meta/instance.json noise_key_fingerprint,
// tenant_instances.noise_key_fingerprint): the hex X25519 public key of the Noise private key — exactly what the
// instance serves as "publicKey": "mkey:<hex>" at /key (§11.3 step 18), so the edge verification can compare it
// without anything secret leaving the helper. content is the file as Headscale reads it.
func NoiseFingerprint(content []byte) (string, error) {
	m := noiseKeyRE.FindSubmatch(bytes.TrimSpace(content))
	if m == nil {
		return "", ErrNoiseKeyInvalid
	}
	var priv [32]byte
	if _, err := hex.Decode(priv[:], m[1]); err != nil {
		return "", ErrNoiseKeyInvalid
	}
	defer clear(priv[:])
	k, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return "", ErrNoiseKeyInvalid
	}
	return hex.EncodeToString(k.PublicKey().Bytes()), nil
}

// fingerprintSpec is the helper container that computes the fingerprint of one instance's Noise key.
func (d *Driver) fingerprintSpec(n agentspec.Names, ref agentspec.Ref, runUID uint32) (OneShot, error) {
	name, err := helperName(ref.Slug, helperFingerprint)
	if err != nil {
		return OneShot{}, err
	}
	uid := strconv.FormatUint(uint64(runUID), 10)
	return OneShot{
		Name: name, Image: d.cfg.HelperImage, Entrypoint: []string{HelperBinary}, Cmd: []string{FingerprintCommand},
		User: uid + ":" + uid, Labels: helperLabels(ref, helperFingerprint),
		Binds:       []Bind{{Source: n.DataDir, Target: "/var/lib/headscale", ReadOnly: true}},
		MemoryBytes: 32 << 20, NanoCPUs: 250_000_000, PIDs: 16, Timeout: fingerprintTimeout, MaxOutput: 4 << 10,
	}, nil
}

// errHelper marks an indeterminate fingerprint (the helper could not run or answered nonsense): the start guard
// fails closed for that cycle but does not treat it as a violation (no flag removed — retried).
type errHelper struct{ err error }

func (e errHelper) Error() string { return "fingerprint helper: " + e.err.Error() }
func (e errHelper) Unwrap() error { return e.err }

// fingerprint runs the helper (once per identity of the key file — see fpCache) and returns the fingerprint, or
// ErrNoiseKeyAbsent/ErrNoiseKeyInvalid (definitive), or an errHelper (indeterminate).
func (d *Driver) fingerprint(ctx context.Context, n agentspec.Names, ref agentspec.Ref, runUID uint32, id fileID) (string, error) {
	if fp, ok := d.fps.get(ref.InstanceID, id); ok {
		return fp, nil
	}
	if d.cfg.HelperImage == "" {
		return "", errHelper{errors.New("no helper image configured (MG_AGENT_HELPER_IMAGE)")}
	}
	spec, err := d.fingerprintSpec(n, ref, runUID)
	if err != nil {
		return "", errHelper{err}
	}
	if err := d.cfg.Engine.EnsureImage(ctx, spec.Image); err != nil {
		return "", errHelper{err}
	}
	res, err := d.cfg.Engine.RunOnce(ctx, spec)
	if err != nil {
		return "", errHelper{err}
	}
	switch out := string(bytes.TrimSuffix(res.Stdout, []byte("\n"))); {
	case res.ExitCode == FingerprintExitAbsent:
		return "", ErrNoiseKeyAbsent
	case res.ExitCode == FingerprintExitInvalid:
		return "", ErrNoiseKeyInvalid
	case res.ExitCode != 0 || res.Truncated || !fingerprintRE.MatchString(out):
		return "", errHelper{fmt.Errorf("exit code %d, %d bytes of output", res.ExitCode, len(res.Stdout))}
	default:
		d.fps.put(ref.InstanceID, id, out)
		return out, nil
	}
}
