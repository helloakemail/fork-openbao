// Command sizeprobe is a native (linux/amd64) twin of wasm/worker that
// imports the same OpenBao packages. It exists only so that binary size can
// be attributed per package with `go tool nm -size`, which cannot read Go
// wasm objects; see wasm/README.md for how the numbers are used.
package main

import (
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/audit"
	auditHttp "github.com/openbao/openbao/v2/internal/builtin/audit/http"
	credAppRole "github.com/openbao/openbao/v2/internal/builtin/credential/approle"
	credCert "github.com/openbao/openbao/v2/internal/builtin/credential/cert"
	credJWT "github.com/openbao/openbao/v2/internal/builtin/credential/jwt"
	credUserpass "github.com/openbao/openbao/v2/internal/builtin/credential/userpass"
	dbPostgres "github.com/openbao/openbao/v2/internal/builtin/database/postgresql"
	logicalDb "github.com/openbao/openbao/v2/internal/builtin/logical/database"
	logicalKv "github.com/openbao/openbao/v2/internal/builtin/logical/kv"
	logicalPki "github.com/openbao/openbao/v2/internal/builtin/logical/pki"
	logicalSsh "github.com/openbao/openbao/v2/internal/builtin/logical/ssh"
	logicalTotp "github.com/openbao/openbao/v2/internal/builtin/logical/totp"
	logicalTransit "github.com/openbao/openbao/v2/internal/builtin/logical/transit"
	"github.com/openbao/openbao/v2/internal/builtin/plugin"
	"github.com/openbao/openbao/v2/internal/helper/configutil"
	vaulthttp "github.com/openbao/openbao/v2/internal/http"
	"github.com/openbao/openbao/v2/internal/physical/postgresql"
	"github.com/openbao/openbao/v2/internal/vault"
)

var sink = []any{
	credAppRole.Factory, credCert.Factory, credJWT.Factory, credUserpass.Factory, dbPostgres.New,
	logicalDb.Factory, logicalKv.Factory, logicalPki.Factory, logicalSsh.Factory, logicalTotp.Factory, logicalTransit.Factory,
	plugin.Factory, auditHttp.Factory, postgresql.NewPostgreSQLBackend, vault.NewCore, vaulthttp.Handler, stdlib.RegisterConnConfig,
	configutil.Listener{}, audit.Factory(nil), logical.Factory(nil),
}

func main() { _ = sink }
