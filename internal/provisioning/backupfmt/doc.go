// Package backupfmt is the format of a per-tenant Headscale backup (P3-T11; master plan §17.1–§17.2, T-15) shared
// by the Host Agent, which writes and checks archives, and the worker, which records them and drives restores.
//
// One backup of an instance is three files under backups/tenants/<instance_id>/ (names derived from the sequence
// only — see ArchiveName):
//
//   - <seq>.tar.age — an age v1 file (X25519 recipients only) holding a tar of data/db.sqlite (a VACUUM INTO or cold
//     copy that passed integrity_check and foreign_key_check), data/noise_private.key, data/derp_server_private.key,
//     config/config.yaml and records/extra-records.json;
//   - <seq>.manifest.json — the Manifest, canonical JSON (encoding/json of the struct, no HTML escaping, no
//     whitespace): tenant, instance, slug, sequence, job, time, method, image and Headscale version, Noise key
//     fingerprint, sha256 and size of every file and of the ciphertext;
//   - <seq>.manifest.sig — the Ed25519 signature of SignContext||manifest by the agent's manifest signing key (the
//     key of the key ceremony, P2-T04a: secrets/agent/manifest_signing_key; verified with MG_BACKUP_MANIFEST_PUBKEY).
//
// Two key paths (§17.1 "mô hình khóa hai đường"): every backup has a random 32-byte data key. The archive is encrypted
// (age) to two recipients — the X25519 public key of the data key (online path) and the platform recovery recipient
// (DR path, private key offline: `age -d -i <identity> <seq>.tar.age | tar x`). The data key is an X25519 private key
// as age encodes it (AGE-SECRET-KEY-1…, see AgeIdentity); the worker wraps it with the tenant's backup key — a 32-byte
// secret in the SecretStore, under the tenant's DEK — with AES-256-GCM bound to tenant, instance and sequence
// (WrapDataKey): a data key wrapped for another tenant, instance or backup does not unwrap, and a data key of another
// backup is no identity of this archive (age: "no identity matched any of the recipients").
//
// Worker AND agent verify the signature and the identity of the manifest before anything is decrypted (Verify, then
// Manifest.Check).
package backupfmt
