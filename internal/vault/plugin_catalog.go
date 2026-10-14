// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	semver "github.com/hashicorp/go-version"
	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/jsonutil"
	"github.com/openbao/openbao/sdk/v2/helper/pluginutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/command/server"
	"github.com/openbao/openbao/v2/internal/helper/pluginutil/oci"
	"github.com/openbao/openbao/v2/internal/helper/versions"
	"github.com/openbao/openbao/v2/internal/vault/barrier"
	"github.com/openbao/openbao/v2/internal/version"
)

const pluginCatalogPath = "core/plugin-catalog/"

const versionLatest = "latest"

var (
	ErrDirectoryNotConfigured       = errors.New("could not set plugin, plugin directory is not configured")
	ErrPluginNotFound               = errors.New("plugin not found in the catalog")
	ErrPluginConnectionNotFound     = errors.New("plugin connection not found for client")
	ErrPluginBadType                = errors.New("unable to determine plugin type")
	ErrSingletonPluginNotReloadable = errors.New("singleton plugin cannot be reloaded")

	// pluginTypes is the subset of consts.PluginTypes that is handled by the
	// plugin catalog.
	pluginTypes = []consts.PluginType{
		consts.PluginTypeUnknown,
		consts.PluginTypeCredential,
		consts.PluginTypeDatabase,
		consts.PluginTypeSecrets,
	}
)

// PluginCatalog keeps a record of plugins known to vault. External plugins need
// to be registered to the catalog before they can be used in backends. Builtin
// plugins are automatically detected and included in the catalog.
type PluginCatalog struct {
	builtinRegistry BuiltinRegistry
	catalogView     barrier.View
	directory       string
	logger          log.Logger

	// externalPlugins holds plugin process connections by a key which is
	// generated from the plugin runner config.
	//
	// This allows plugins that suppport multiplexing to use a single grpc
	// connection to communicate with multiple "backends". Each backend
	// configuration using the same plugin will be routed to the existing
	// plugin process.
	externalPlugins map[externalPluginsKey]*externalPlugin
	mlockPlugins    bool

	lock    sync.RWMutex
	wrapper pluginutil.RunnerUtil
}

// Only plugins running with identical PluginRunner config can be multiplexed,
// so we use the PluginRunner input as the key for the external plugins map.
//
// However, to be a map key, it must be comparable:
// https://go.dev/ref/spec#Comparison_operators.
// In particular, the PluginRunner struct has slices and a function which are not
// comparable, so we need to transform it into a struct which is.
type externalPluginsKey struct {
	name    string
	typ     consts.PluginType
	version string
	command string
	args    string
	env     string
	sha256  string
	builtin bool
}

func makeExternalPluginsKey(p *pluginutil.PluginRunner) (externalPluginsKey, error) {
	args, err := json.Marshal(p.Args)
	if err != nil {
		return externalPluginsKey{}, err
	}

	env, err := json.Marshal(p.Env)
	if err != nil {
		return externalPluginsKey{}, err
	}

	return externalPluginsKey{
		name:    p.Name,
		typ:     p.Type,
		version: p.Version,
		command: p.Command,
		args:    string(args),
		env:     string(env),
		sha256:  hex.EncodeToString(p.Sha256),
		builtin: p.Builtin,
	}, nil
}

func wrapFactoryCheckPerms(core *Core, f logical.Factory) logical.Factory {
	return func(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
		pluginName := conf.Config["plugin_name"]
		pluginVersion := conf.Config["plugin_version"]
		pluginTypeRaw := conf.Config["plugin_type"]
		pluginType, err := consts.ParsePluginType(pluginTypeRaw)
		if err != nil {
			return nil, err
		}

		pluginDescription := fmt.Sprintf("%s plugin %s", pluginTypeRaw, pluginName)
		if pluginVersion != "" {
			pluginDescription += " version " + pluginVersion
		}

		plugin, err := core.pluginCatalog.Get(ctx, pluginName, pluginType, pluginVersion)
		if err != nil {
			return nil, fmt.Errorf("failed to find %s in plugin catalog: %w", pluginDescription, err)
		}
		if plugin == nil {
			return nil, fmt.Errorf("failed to find %s in plugin catalog", pluginDescription)
		}

		command, err := filepath.Rel(core.pluginCatalog.directory, plugin.Command)
		if err != nil {
			return nil, fmt.Errorf("failed to compute plugin command: %w", err)
		}

		if err := core.CheckPluginPerms(command); err != nil {
			return nil, err
		}
		return f(ctx, conf)
	}
}

func (c *Core) setupPluginCatalog(ctx context.Context) error {
	c.pluginCatalog = &PluginCatalog{
		builtinRegistry: c.builtinRegistry,
		catalogView:     barrier.NewView(c.barrier, pluginCatalogPath),
		directory:       c.pluginDirectory,
		logger:          c.logger,
		// mlock is not currently used in OpenBao, but this setting is retained for Vault compat
		mlockPlugins: false,
		wrapper:      logical.StaticSystemView{VersionString: version.GetVersion().Version},
	}

	// Run upgrade if untyped plugins exist
	err := c.pluginCatalog.UpgradePlugins(ctx, c.logger)
	if err != nil {
		c.logger.Error("error while upgrading plugin storage", "error", err)
		return err
	}

	c.logger.Info("successfully setup plugin catalog", "plugin-directory", c.pluginDirectory)

	return nil
}

func (c *Core) ReloadPlugins() {
	// Ensure we are already unsealed
	c.stateLock.RLock()
	defer c.stateLock.RUnlock()

	ctx := c.activeContext.Load()
	if c.Sealed() || (c.standby.Load() && !c.StandbyReadsEnabled()) || ctx.IsNil() {
		return
	}

	if err := c.registerDeclarativePlugins(ctx, c.Standby()); err != nil {
		c.logger.Error("failed to set up plugins on reload", "error", err)
	}
}

func (c *Core) registerDeclarativePlugins(ctx context.Context, standby bool) error {
	config := c.rawConfig.Load()
	if config == nil {
		return nil
	}

	if !config.PluginAutoRegister {
		return nil
	}

	logger := c.logger.Named("plugins")

	logger.Debug("starting declarative plugin registration")
	defer logger.Debug("declarative plugin registration completed")

	c.pluginCatalog.lock.Lock()
	defer c.pluginCatalog.lock.Unlock()

	if err := c.pluginCatalog.registerDeclarativePlugins(ctx, config.Plugins, standby); err != nil {
		return fmt.Errorf("failed to set up declarative plugins: %w", err)
	}

	return nil
}

func (c *PluginCatalog) registerDeclarativePlugins(ctx context.Context, plugins []*server.PluginConfig, standby bool) error {
	// Register any missing plugins and update existing ones.
	for index, plugin := range plugins {
		if err := func() error {
			pluginType, err := consts.ParsePluginType(plugin.Type)
			if err != nil {
				return err
			}

			if !slices.Contains(pluginTypes, pluginType) {
				// Skip registering plugins that are not handled by the plugin
				// catalog, such as KMS plugins.
				return nil
			}

			sha256, err := hex.DecodeString(plugin.SHA256Sum)
			if err != nil {
				return fmt.Errorf("invalid plugin sha256: %w", err)
			}

			// Check if the entry exists in storage already.
			var update bool
			pluginInfo, err := c.get(ctx, plugin.Name, pluginType, plugin.Version)
			if err != nil {
				return fmt.Errorf("failed getting plugin: %w", err)
			}

			if pluginInfo != nil {
				if !pluginInfo.Declarative {
					return errors.New("conflicts with existing non-declarative plugin; do not specify existing plugins in the server configuration")
				}

				// Check if we need to update any fields.
				update = !slices.Equal(plugin.Args, pluginInfo.Args) ||
					!slices.Equal(plugin.Env, pluginInfo.Env) ||
					!bytes.Equal(sha256, pluginInfo.Sha256) ||
					(plugin.Image != nil) != pluginInfo.Oci ||
					(plugin.Image == nil && plugin.Command != pluginInfo.Command)
				if update {
					c.logger.Info("updating existing plugin", "name", plugin.Name, "type", plugin.Type, "version", plugin.Version, "sha256", plugin.SHA256Sum)
				}
			} else {
				c.logger.Info("registering new declarative plugin", "name", plugin.Name, "type", plugin.Type, "version", plugin.Version, "sha256", plugin.SHA256Sum)
				update = true
			}

			if update {
				if standby {
					c.logger.Warn("plugin out of date in storage versus standby node configuration; this may be a false-positive depending on data replication state", "name", plugin.Name, "type", plugin.Type, "version", plugin.Version, "sha256", plugin.SHA256Sum)
					return nil
				}

				_, err = c.setInternal(ctx, plugin.Name, pluginType, plugin.Version, plugin.CommandPath(), plugin.Args, plugin.Env, sha256, plugin.Image != nil /* OCI */, true /* declarative */)
				if err != nil {
					return fmt.Errorf("failed to register new plugin: %w", err)
				}
			}

			return nil
		}(); err != nil {
			return fmt.Errorf("[plugin %d (name: %v / type: %v)]: %w", index, plugin.Name, plugin.Type, err)
		}
	}

	// Check if we need to remove any plugins.
	for _, pluginType := range pluginTypes {
		if err := func() error {
			storedPlugins, err := c.listInternal(ctx, pluginType)
			if err != nil {
				return fmt.Errorf("failed to list plugins: %w", err)
			}

			for index, storedPlugin := range storedPlugins {
				if !storedPlugin.Declarative {
					continue
				}

				if err := func() error {
					// Check if we have a matching plugin.
					found := false
					for _, configPlugin := range plugins {
						if configPlugin.Name == storedPlugin.Name && configPlugin.Type == storedPlugin.Type && configPlugin.Version == storedPlugin.Version {
							found = true
							break
						}
					}

					// Remove the stored plugin.
					if !found {
						if standby {
							c.logger.Warn("plugin present in storage but not standby node configuration; this may be a false-positive depending on data replication state", "name", storedPlugin.Name, "type", storedPlugin.Type, "version", storedPlugin.Version)
							return nil
						}

						c.logger.Info("removing plugin present in storage but no longer present in configuration", "name", storedPlugin.Name, "type", storedPlugin.Type, "version", storedPlugin.Version)

						if err := c.deleteInternal(ctx, storedPlugin.Name, pluginType, storedPlugin.Version); err != nil {
							return fmt.Errorf("failed to delete plugin: %w", err)
						}
					}

					return nil
				}(); err != nil {
					return fmt.Errorf("[stored plugin %d (name: %v / version: %v)]: %w", index, storedPlugin.Name, storedPlugin.Version, err)
				}
			}

			return nil
		}(); err != nil {
			return fmt.Errorf("while listing plugins of type %v: %w", pluginType, err)
		}
	}

	return nil
}

// UpdatePlugins will loop over all the plugins of unknown type and attempt to
// upgrade them to typed plugins
func (c *PluginCatalog) UpgradePlugins(ctx context.Context, logger log.Logger) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// If the directory isn't set we can skip the upgrade attempt
	if c.directory == "" {
		return nil
	}

	// List plugins from old location
	pluginsRaw, err := c.catalogView.List(ctx, "")
	if err != nil {
		return err
	}
	plugins := make([]string, 0, len(pluginsRaw))
	for _, p := range pluginsRaw {
		if !strings.HasSuffix(p, "/") {
			plugins = append(plugins, p)
		}
	}

	logger.Info("upgrading plugin information", "plugins", plugins)

	var retErr error
	for _, pluginName := range plugins {
		pluginRaw, err := c.catalogView.Get(ctx, pluginName)
		if err != nil {
			retErr = multierror.Append(fmt.Errorf("failed to load plugin entry: %w", err))
			continue
		}

		plugin := new(pluginutil.PluginRunner)
		if err := jsonutil.DecodeJSON(pluginRaw.Value, plugin); err != nil {
			retErr = multierror.Append(fmt.Errorf("failed to decode plugin entry: %w", err))
			continue
		}

		// prepend the plugin directory to the command
		cmdOld := plugin.Command
		plugin.Command = filepath.Join(c.directory, plugin.Command)

		// Upgrade the storage. At this point we don't know what type of plugin this is so pass in the unknown type.
		runner, err := c.setInternal(ctx, pluginName, consts.PluginTypeUnknown, plugin.Version, cmdOld, plugin.Args, plugin.Env, plugin.Sha256, false /* oci */, false /* declarative */)
		if err != nil {
			if errors.Is(err, ErrPluginBadType) {
				retErr = multierror.Append(retErr, fmt.Errorf("could not upgrade plugin %s: plugin of unknown type", pluginName))
				continue
			}

			retErr = multierror.Append(retErr, fmt.Errorf("could not upgrade plugin %s: %s", pluginName, err))
			continue
		}

		err = c.catalogView.Delete(ctx, pluginName)
		if err != nil {
			logger.Error("could not remove plugin", "plugin", pluginName, "error", err)
		}

		logger.Info("upgraded plugin type", "plugin", pluginName, "type", runner.Type.String())
	}

	return retErr
}

// Get retrieves a plugin with the specified name from the catalog. It first
// looks for external plugins with this name and then looks for builtin plugins.
// It returns a PluginRunner or an error if no plugin was found.
func (c *PluginCatalog) Get(ctx context.Context, name string, pluginType consts.PluginType, version string) (*pluginutil.PluginRunner, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.get(ctx, name, pluginType, version)
}

func (c *PluginCatalog) get(ctx context.Context, name string, pluginType consts.PluginType, version string) (*pluginutil.PluginRunner, error) {
	// If the directory isn't set only look for builtin plugins.
	if c.directory != "" {
		// Look for external plugins in the barrier.
		runner, err := c.getExternal(ctx, name, pluginType, version)
		switch {
		case err != nil:
			return nil, err
		case runner != nil:
			return runner, err
		}
	}

	return c.getBuiltin(ctx, name, pluginType, version), nil
}

func (c *PluginCatalog) getExternal(ctx context.Context, name string, pluginType consts.PluginType, version string) (*pluginutil.PluginRunner, error) {
	storageKey := path.Join(pluginType.String(), name)

	if version == versionLatest {
		versions, err := c.catalogView.List(ctx, storageKey+"/")
		if err != nil {
			return nil, fmt.Errorf("failed to list available plugin versions: %w", err)
		}

		// Find the latest available version.
		version = ""
		var latest *semver.Version

		for _, v := range versions {
			sv, err := semver.NewSemver(v)
			switch {
			case err != nil:
				return nil, fmt.Errorf("bad plugin version in storage: %w", err)
			case latest == nil, sv.GreaterThan(latest):
				latest, version = sv, v
			}
		}
	}

	if version != "" {
		storageKey = path.Join(storageKey, version)
	}

	out, err := c.catalogView.Get(ctx, storageKey)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve plugin %q: %w", name, err)
	}
	if out == nil && version == "" {
		// Also look for external plugins under what their name would have been if they
		// were registered before plugin types existed.
		out, err = c.catalogView.Get(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve plugin %q: %w", name, err)
		}
	}
	if out == nil {
		return nil, nil
	}

	entry := new(pluginutil.PluginRunner)
	if err := jsonutil.DecodeJSON(out.Value, entry); err != nil {
		return nil, fmt.Errorf("failed to decode plugin entry: %w", err)
	}
	if entry.Type != pluginType && entry.Type != consts.PluginTypeUnknown {
		return nil, nil
	}

	entry.Command, err = c.checkCommandDirectory(entry.Name, pluginType, entry.Command, entry.Sha256, entry.Oci)
	if err != nil {
		return nil, err
	}

	return entry, nil
}

func (c *PluginCatalog) getBuiltin(ctx context.Context, name string, pluginType consts.PluginType, version string) *pluginutil.PluginRunner {
	builtinVersion := versions.GetBuiltinVersion(pluginType, name)

	switch version {
	case "":
	case builtinVersion:
		// Don't return the builtin if it's shadowed by an unversioned plugin.
		unversioned, err := c.getExternal(ctx, name, pluginType, "")
		if err == nil && unversioned != nil {
			return nil
		}
	default:
		return nil
	}

	// Look for builtin plugins.
	factory, ok := c.builtinRegistry.Get(name, pluginType)
	if !ok {
		return nil
	}

	return &pluginutil.PluginRunner{
		Name:           name,
		Type:           pluginType,
		Builtin:        true,
		BuiltinFactory: factory,
		Version:        builtinVersion,
	}
}

// Get the plugin types associated with a plugin name
func (c *PluginCatalog) TypesFromName(ctx context.Context, name string) ([]consts.PluginType, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.typesFromNameLocked(ctx, name)
}

// Get the plugin types associated with a plugin name
// Caller must have a read lock on c.lock
func (c *PluginCatalog) typesFromNameLocked(ctx context.Context, name string) ([]consts.PluginType, error) {
	typeSet := make(map[consts.PluginType]struct{})

	if c.directory != "" {
		// Check for matching external untyped unversioned plugin (registered before plugin types existed)
		// we check this first because these storage entries are not under a plugin type directory
		out, err := c.catalogView.Get(ctx, name)
		if err != nil {
			return nil, err
		}
		if out != nil {
			// Parse the entry to figure out the type
			entry := new(pluginutil.PluginRunner)
			if err := jsonutil.DecodeJSON(out.Value, entry); err != nil {
				return nil, fmt.Errorf("failed to decode plugin entry: %w", err)
			}
			if entry.Type != consts.PluginTypeUnknown {
				typeSet[entry.Type] = struct{}{}
			}
		}
	}

	for _, pluginType := range consts.PluginTypes {
		// Skip type unknown
		if pluginType == consts.PluginTypeUnknown {
			continue
		}

		// Check for plugin existence across plugin types.
		hasPlugin, err := c.hasPluginWithTypeLocked(ctx, name, pluginType)
		if err != nil {
			return nil, err
		}
		if hasPlugin {
			typeSet[pluginType] = struct{}{}
		}
	}

	var pluginTypes []consts.PluginType
	for k := range typeSet {
		pluginTypes = append(pluginTypes, k)
	}

	return pluginTypes, nil
}

// Check if a plugin of a specific type and name is available in the plugin catalog.
// Caller must have a read lock on c.lock
func (c *PluginCatalog) hasPluginWithTypeLocked(ctx context.Context, name string, pluginType consts.PluginType) (bool, error) {
	// If the directory isn't set only look for builtin plugins.
	if c.directory != "" {
		storagePath := path.Join(pluginType.String(), name)

		// Check for matching unversioned plugin
		out, err := c.catalogView.Get(ctx, storagePath)
		if err != nil {
			return false, err
		}
		if out != nil {
			return true, nil
		}

		// Check if there is at least one matching versioned plugin
		entries, err := c.catalogView.List(ctx, storagePath+"/")
		if err != nil {
			return false, err
		}
		if len(entries) > 0 {
			return true, nil
		}
	}

	// Finally, check for matching builtin plugins
	if _, ok := c.builtinRegistry.Get(name, pluginType); ok {
		return true, nil
	}
	return false, nil
}

// Set registers a new external plugin with the catalog, or updates an existing
// external plugin. It takes the name, command and SHA256 of the plugin.
func (c *PluginCatalog) Set(ctx context.Context, name string, pluginType consts.PluginType, version string, command string, args []string, env []string, sha256 []byte, oci bool) error {
	if c.directory == "" {
		return ErrDirectoryNotConfigured
	}

	switch {
	case strings.Contains(name, ".."):
		fallthrough
	case strings.Contains(command, ".."):
		return consts.ErrPathContainsParentReferences
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	_, err := c.setInternal(ctx, name, pluginType, version, command, args, env, sha256, oci, false /* not declarative */)
	return err
}

func (c *PluginCatalog) checkCommandDirectory(name string, pluginType consts.PluginType, command string, sha256 []byte, isOci bool) (string, error) {
	// Best effort check to make sure the command isn't breaking out of the
	// configured plugin directory.
	commandFull := filepath.Join(c.directory, command)
	sym, err := filepath.EvalSymlinks(commandFull)
	if err != nil {
		return "", fmt.Errorf("error while validating the command path: %w", err)
	}
	symAbs, err := filepath.Abs(filepath.Dir(sym))
	if err != nil {
		return "", fmt.Errorf("error while validating the command path: %w", err)
	}

	ok := symAbs == c.directory
	if !ok && isOci {
		ok = symAbs == filepath.Join(c.directory, oci.PluginCacheDir)
		if !ok && len(sha256) > 0 {
			ok = symAbs == filepath.Join(
				c.directory, oci.PluginCacheDir, fmt.Sprintf("%s-%s", pluginType.String(), name), hex.EncodeToString(sha256)[:8],
			)
		}
	}

	if !ok {
		return "", errors.New("cannot execute files outside of configured plugin directory")
	}

	return commandFull, nil
}

func (c *PluginCatalog) setInternal(ctx context.Context, name string, pluginType consts.PluginType, version string, command string, args []string, env []string, sha256 []byte, isOci bool, declarative bool) (*pluginutil.PluginRunner, error) {
	commandFull, err := c.checkCommandDirectory(name, pluginType, command, sha256, isOci)
	if err != nil {
		return nil, err
	}

	// entryTmp should only be used for the below type and version checks, it uses the
	// full command instead of the relative command.
	entryTmp := &pluginutil.PluginRunner{
		Name:        name,
		Command:     commandFull,
		Args:        args,
		Env:         env,
		Sha256:      sha256,
		Builtin:     false,
		Oci:         isOci,
		Declarative: declarative,
	}
	// If the plugin type is unknown, we want to attempt to determine the type
	if pluginType == consts.PluginTypeUnknown {
		pluginType, err = c.getPluginTypeFromUnknown(ctx, entryTmp)
		if err != nil {
			return nil, err
		}
		if pluginType == consts.PluginTypeUnknown {
			return nil, ErrPluginBadType
		}
	}

	// getting the plugin version is best-effort, so errors are not fatal
	runningVersion := logical.EmptyPluginVersion
	var versionErr error
	switch pluginType {
	case consts.PluginTypeSecrets, consts.PluginTypeCredential:
		runningVersion, versionErr = c.getBackendRunningVersion(ctx, entryTmp)
	case consts.PluginTypeDatabase:
		runningVersion, versionErr = c.getDatabaseRunningVersion(ctx, entryTmp)
	case consts.PluginTypeKMS:
		return nil, fmt.Errorf("KMS plugins cannot be registered via the plugin catalog")
	default:
		return nil, fmt.Errorf("unknown plugin type: %v", pluginType)
	}
	if versionErr != nil {
		c.logger.Warn("Error determining plugin version", "error", versionErr)
	} else if version != "" && runningVersion.Version != "" && version != runningVersion.Version {
		c.logger.Warn("Plugin self-reported version did not match requested version", "plugin", name, "requestedVersion", version, "reportedVersion", runningVersion.Version)
		return nil, fmt.Errorf("plugin version mismatch: %s reported version (%s) did not match requested version (%s)", name, runningVersion.Version, version)
	} else if version == "" && runningVersion.Version != "" {
		version = runningVersion.Version
		_, err := semver.NewVersion(version)
		if err != nil {
			return nil, fmt.Errorf("plugin self-reported version %q is not a valid semantic version: %w", version, err)
		}

	}

	entry := &pluginutil.PluginRunner{
		Name:        name,
		Type:        pluginType,
		Version:     version,
		Command:     command,
		Args:        args,
		Env:         env,
		Sha256:      sha256,
		Builtin:     false,
		Oci:         isOci,
		Declarative: declarative,
	}

	buf, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to encode plugin entry: %w", err)
	}

	storageKey := path.Join(pluginType.String(), name)
	if version != "" {
		storageKey = path.Join(storageKey, version)
	}
	logicalEntry := logical.StorageEntry{
		Key:   storageKey,
		Value: buf,
	}
	if err := c.catalogView.Put(ctx, &logicalEntry); err != nil {
		return nil, fmt.Errorf("failed to persist plugin entry: %w", err)
	}
	return entry, nil
}

// Delete is used to remove an external plugin from the catalog. Builtin plugins
// can not be deleted.
func (c *PluginCatalog) Delete(ctx context.Context, name string, pluginType consts.PluginType, pluginVersion string) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	return c.deleteInternal(ctx, name, pluginType, pluginVersion)
}

func (c *PluginCatalog) deleteInternal(ctx context.Context, name string, pluginType consts.PluginType, pluginVersion string) error {
	// Check the name under which the plugin exists, but if it's unfound, don't return any error.
	pluginKey := path.Join(pluginType.String(), name)
	if pluginVersion != "" {
		pluginKey = path.Join(pluginKey, pluginVersion)
	}
	out, err := c.catalogView.Get(ctx, pluginKey)
	if err != nil || out == nil {
		pluginKey = name
	}

	return c.catalogView.Delete(ctx, pluginKey)
}

func (c *PluginCatalog) ListVersionedPlugins(ctx context.Context, pluginType consts.PluginType) ([]pluginutil.VersionedPlugin, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.listInternal(ctx, pluginType)
}

func (c *PluginCatalog) listInternal(ctx context.Context, pluginType consts.PluginType) ([]pluginutil.VersionedPlugin, error) {
	var result []pluginutil.VersionedPlugin

	// Collect keys for external plugins in the barrier.
	keys, err := logical.CollectKeys(ctx, c.catalogView)
	if err != nil {
		return nil, err
	}

	unversionedPlugins := make(map[string]struct{})
	for _, key := range keys {
		var semanticVersion *semver.Version

		entry, err := c.catalogView.Get(ctx, key)
		if err != nil || entry == nil {
			continue
		}

		plugin := new(pluginutil.PluginRunner)
		if err := jsonutil.DecodeJSON(entry.Value, plugin); err != nil {
			return nil, fmt.Errorf("failed to decode plugin entry: %w", err)
		}

		if plugin.Version == "" {
			semanticVersion, err = semver.NewVersion("0.0.0")
			if err != nil {
				return nil, err
			}
		} else {
			semanticVersion, err = semver.NewVersion(plugin.Version)
			if err != nil {
				return nil, fmt.Errorf("unexpected error parsing version from plugin catalog entry %q: %w", key, err)
			}
		}

		// Only list user-added plugins if they're of the given type.
		if plugin.Type != consts.PluginTypeUnknown && plugin.Type != pluginType {
			continue
		}

		result = append(result, pluginutil.VersionedPlugin{
			Name:            plugin.Name,
			Type:            plugin.Type.String(),
			Version:         plugin.Version,
			SHA256:          hex.EncodeToString(plugin.Sha256),
			SemanticVersion: semanticVersion,
			Oci:             plugin.Oci,
			Declarative:     plugin.Declarative,
		})

		if plugin.Version == "" {
			unversionedPlugins[plugin.Name] = struct{}{}
		}
	}

	// Get the builtin plugins.
	builtinPlugins := c.builtinRegistry.Keys(pluginType)
	for _, plugin := range builtinPlugins {
		// Unversioned plugins fully replace builtins of the same name.
		if _, ok := unversionedPlugins[plugin]; ok {
			continue
		}

		version := versions.GetBuiltinVersion(pluginType, plugin)
		semanticVersion, err := semver.NewVersion(version)
		deprecationStatus, _ := c.builtinRegistry.DeprecationStatus(plugin, pluginType)
		if err != nil {
			return nil, err
		}
		result = append(result, pluginutil.VersionedPlugin{
			Name:              plugin,
			Type:              pluginType.String(),
			Version:           version,
			Builtin:           true,
			SemanticVersion:   semanticVersion,
			DeprecationStatus: deprecationStatus.String(),
			Oci:               false,
			Declarative:       false,
		})
	}

	return result, nil
}
