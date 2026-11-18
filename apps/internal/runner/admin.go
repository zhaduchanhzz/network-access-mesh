package runner

// P4-T03a wiring: the SecretStore adapter of a tenant IdP's client secret (the approval actions and the notification of
// the deciders are adminapi.ApprovalActions / adminapi.NotifyDeciders).

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/zhaduchanhzz/network-access-mesh/internal/idp"
	"github.com/zhaduchanhzz/network-access-mesh/internal/secrets"
	"github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)

// idpClientSecrets stores the client secret of a tenant's external IdP in the SecretStore under the IdP's own name
// (idp.AdminClientSecretName, owner = the tenant — the only reference the login callback and the CHECK of 0007 accept):
// version 1 the first time, the next version afterwards.
type idpClientSecrets struct{ s *secrets.Store }

var _ tenants.ClientSecrets = idpClientSecrets{}

func (c idpClientSecrets) Store(ctx context.Context, tenantID, idpID uuid.UUID, secret []byte) (string, error) {
	if c.s == nil || tenantID == uuid.Nil {
		return "", errors.New("idp client secret: no SecretStore or no tenant")
	}
	name := idp.AdminClientSecretName(idpID)
	latest, err := c.s.Latest(ctx, tenantID, name)
	var ref secrets.Ref
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		ref = secrets.TenantRef(tenantID, name, 1)
		err = c.s.Put(ctx, ref, secret)
	case err == nil:
		ref, err = c.s.Rotate(ctx, latest, secret)
	}
	if err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (c idpClientSecrets) Destroy(ctx context.Context, ref string) error {
	r, err := secrets.ParseRef(ref)
	if err != nil || c.s == nil {
		return err
	}
	return c.s.Destroy(ctx, r)
}
