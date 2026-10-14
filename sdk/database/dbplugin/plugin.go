// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package dbplugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
)

var (
	ErrPluginShutdown          = errors.New("plugin shutdown")
	ErrPluginStaticUnsupported = errors.New("database plugin does not support Static Accounts")
)

// Database is the interface that all database objects must implement.
type Database interface {
	// Type returns the TypeName for the particular database backend
	// implementation. This type name is usually set as a constant within the
	// database backend implementation, e.g. "mysql" for the MySQL database
	// backend.
	Type() (string, error)

	// CreateUser is called on `$ bao read database/creds/:role-name` and it's
	// also the first time anything is touched from `$ bao write
	// database/roles/:role-name`. This is likely to be the highest-throughput
	// method for most plugins.
	CreateUser(ctx context.Context, statements Statements, usernameConfig UsernameConfig, expiration time.Time) (username string, password string, err error)

	// RenewUser is triggered by a renewal call to the API. In many database
	// backends, this triggers a call on the underlying database that extends a
	// VALID UNTIL clause on a user. However, if no such need exists, setting
	// this as a NO-OP means that when renewal is called, the lease renewal time
	// is pushed further out as appropriate, thus pushing out the time until the
	// RevokeUser method is called.
	RenewUser(ctx context.Context, statements Statements, username string, expiration time.Time) error

	// RevokeUser is triggered either automatically by a lease expiration, or by
	// a revocation call to the API.
	RevokeUser(ctx context.Context, statements Statements, username string) error

	// RotateRootCredentials is triggered by a root credential rotation call to
	// the API.
	RotateRootCredentials(ctx context.Context, statements []string) (config map[string]any, err error)

	// GenerateCredentials returns a generated password for the plugin. This is
	// used in combination with SetCredentials to set a specific password for a
	// database user and preserve the password in WAL entries.
	GenerateCredentials(ctx context.Context) (string, error)

	// SetCredentials uses provided information to create or set the credentials
	// for a database user. Unlike CreateUser, this method requires both a
	// username and a password given instead of generating them. This is used for
	// creating and setting the password of static accounts, as well as rolling
	// back passwords in the database in the event an updated database fails to
	// save in Vault's storage.
	SetCredentials(ctx context.Context, statements Statements, staticConfig StaticUserConfig) (username string, password string, err error)

	// Init is called on `$ bao write database/config/:db-name`, or when you
	// do a creds call after Vault's been restarted. The config provided won't
	// hold all the keys and values provided in the API call, some will be
	// stripped by the database engine before the config is provided. The config
	// returned will be stored, which will persist it across shutdowns.
	Init(ctx context.Context, config map[string]any, verifyConnection bool) (saveConfig map[string]any, err error)

	// Close attempts to close the underlying database connection that was
	// established by the backend.
	Close() error
}

// PluginFactory is used to build plugin database types. It wraps the database
// object in a logging and metrics middleware.
func PluginFactory(ctx context.Context, pluginName string, pluginVersion string, sys pluginutil.LookRunnerUtil, logger log.Logger) (Database, error) {
	return PluginFactoryVersion(ctx, pluginName, "", sys, logger)
}

// PluginFactory is used to build plugin database types with a version specified.
// It wraps the database object in a logging and metrics middleware.
func PluginFactoryVersion(ctx context.Context, pluginName string, pluginVersion string, sys pluginutil.LookRunnerUtil, logger log.Logger) (Database, error) {
	// Look for plugin in the plugin catalog
	pluginRunner, err := sys.LookupPluginVersion(ctx, pluginName, consts.PluginTypeDatabase, pluginVersion)
	if err != nil {
		return nil, err
	}

	namedLogger := logger.Named(pluginName)

	var transport string
	var db Database
	if pluginRunner.Builtin {
		// Plugin is builtin so we can retrieve an instance of the interface
		// from the pluginRunner. Then cast it to a Database.
		dbRaw, err := pluginRunner.BuiltinFactory()
		if err != nil {
			return nil, fmt.Errorf("error initializing plugin: %w", err)
		}

		var ok bool
		db, ok = dbRaw.(Database)
		if !ok {
			return nil, fmt.Errorf("unsupported database type: %q", pluginName)
		}

		transport = "builtin"

	} else {
		db, transport, err = newExternalDatabase(ctx, sys, pluginRunner, namedLogger)
		if err != nil {
			return nil, err
		}
	}

	typeStr, err := db.Type()
	if err != nil {
		return nil, fmt.Errorf("error getting plugin type: %w", err)
	}

	// Wrap with metrics middleware
	db = &databaseMetricsMiddleware{
		next:    db,
		typeStr: typeStr,
	}

	// Wrap with tracing middleware
	if namedLogger.IsTrace() {
		db = &databaseTracingMiddleware{
			next:   db,
			logger: namedLogger.With("transport", transport),
		}
	}

	return db, nil
}
