package policies

// database/sql outside internal/store: rejected by the driver rule (P2-T03).
import _ "database/sql"
