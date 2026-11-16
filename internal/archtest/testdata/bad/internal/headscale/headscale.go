package headscale

import (
	_ "github.com/jackc/pgx/v5/pgtype" // value types are allowed outside internal/store (P2-T03)
	_ "github.com/zhaduchanhzz/network-access-mesh/internal/tenants"
)
