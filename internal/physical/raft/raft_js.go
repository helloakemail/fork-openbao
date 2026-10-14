// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build js

// Package raft on js/wasm is a stub. Integrated (raft) storage needs local
// disk, mmap and bbolt, none of which exist in a WebAssembly sandbox such as
// a Cloudflare Worker. This file keeps the exported data types that the
// vault and http packages reference so that they compile unchanged, and
// turns every operation on a RaftBackend into a "not supported" error.
// The WASM build must use an external physical backend (PostgreSQL).

package raft

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	autopilot "github.com/hashicorp/raft-autopilot"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/physical"
	"github.com/openbao/openbao/v2/internal/helper/metricsutil"
	"github.com/openbao/openbao/v2/internal/vault/cluster"
	"github.com/openbao/openbao/v2/internal/vault/seal"
)

// ErrNotSupported is returned by every RaftBackend operation on js/wasm.
var ErrNotSupported = errors.New("raft storage is not supported on js/wasm")

// ErrRaftAutopilotNotInitialized mirrors the native package.
var ErrRaftAutopilotNotInitialized = errors.New("raft storage autopilot is not initialized")

const (
	CleanupDeadServersUnset CleanupDeadServersValue = 0
	CleanupDeadServersTrue  CleanupDeadServersValue = 1
	CleanupDeadServersFalse CleanupDeadServersValue = 2

	NonVoterPath = "autopilot/non-voters"
)

func (c CleanupDeadServersValue) Value() bool { return c == CleanupDeadServersTrue }

type restoreCallback func(context.Context) error

// RaftBackend is an empty placeholder on js/wasm.
type RaftBackend struct{}

var _ physical.Backend = (*RaftBackend)(nil)

func NewRaftBackend(conf map[string]string, logger log.Logger) (physical.Backend, error) {
	return nil, ErrNotSupported
}

func EnsurePath(path string, dir bool) error { return ErrNotSupported }

func GenerateTLSKey() (*TLSKey, error) { return nil, ErrNotSupported }

func (k *TLSKeyring) GetActive() *TLSKey {
	if k == nil {
		return nil
	}
	for _, key := range k.Keys {
		if key.ID == k.ActiveKeyID {
			return key
		}
	}
	return nil
}

// physical.Backend
func (b *RaftBackend) Put(ctx context.Context, entry *physical.Entry) error { return ErrNotSupported }
func (b *RaftBackend) Get(ctx context.Context, key string) (*physical.Entry, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) Delete(ctx context.Context, key string) error { return ErrNotSupported }
func (b *RaftBackend) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) ListPage(ctx context.Context, prefix string, after string, limit int) ([]string, error) {
	return nil, ErrNotSupported
}

// Cluster lifecycle and introspection.
func (b *RaftBackend) Close() error                                                 { return nil }
func (b *RaftBackend) SetEffectiveSDKVersion(sdkVersion string)                     {}
func (b *RaftBackend) NodeID() string                                               { return "" }
func (b *RaftBackend) Initialized() bool                                            { return false }
func (b *RaftBackend) SetServerAddressProvider(provider raft.ServerAddressProvider) {}
func (b *RaftBackend) Bootstrap(peers []Peer) error                                 { return ErrNotSupported }
func (b *RaftBackend) SetRestoreCallback(restoreCb restoreCallback)                 {}
func (b *RaftBackend) StartRecoveryCluster(ctx context.Context, peer Peer) error {
	return ErrNotSupported
}
func (b *RaftBackend) HasState() (bool, error)                                   { return false, nil }
func (b *RaftBackend) SetupCluster(ctx context.Context, opts SetupOpts) error    { return ErrNotSupported }
func (b *RaftBackend) TeardownCluster(clusterListener cluster.ClusterHook) error { return nil }
func (b *RaftBackend) CommittedIndex() uint64                                    { return 0 }
func (b *RaftBackend) AppliedIndex() uint64                                      { return 0 }
func (b *RaftBackend) RemovePeer(ctx context.Context, peerID string) error       { return ErrNotSupported }
func (b *RaftBackend) GetConfiguration(ctx context.Context) (*RaftConfigurationResponse, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) AddPeer(ctx context.Context, peerID, clusterAddr string, voter bool) error {
	return ErrNotSupported
}
func (b *RaftBackend) Peers(ctx context.Context) ([]Peer, error) { return nil, ErrNotSupported }
func (b *RaftBackend) SnapshotHTTP(out *logical.HTTPResponseWriter, access seal.Access) error {
	return ErrNotSupported
}
func (b *RaftBackend) WriteSnapshotToTemp(in io.ReadCloser, access seal.Access) (*os.File, func(), raft.SnapshotMeta, error) {
	return nil, func() {}, raft.SnapshotMeta{}, ErrNotSupported
}
func (b *RaftBackend) RestoreSnapshot(ctx context.Context, metadata raft.SnapshotMeta, snap io.Reader) error {
	return ErrNotSupported
}
func (b *RaftBackend) SetDesiredSuffrage(nonVoter bool) error { return ErrNotSupported }
func (b *RaftBackend) DesiredSuffrage() string                { return "" }

// Autopilot.
func (b *RaftBackend) SetAutopilotConfig(config *AutopilotConfig) {}
func (b *RaftBackend) AutopilotConfig() *AutopilotConfig          { return nil }
func (b *RaftBackend) AutopilotDisabled() bool                    { return true }
func (b *RaftBackend) StopAutopilot()                             {}
func (b *RaftBackend) DisableAutopilot()                          {}
func (b *RaftBackend) GetAutopilotServerState(ctx context.Context) (*AutopilotState, error) {
	return nil, ErrRaftAutopilotNotInitialized
}
func (b *RaftBackend) SetupAutopilot(ctx context.Context, storageConfig *AutopilotConfig, followerStates *FollowerStates, disable bool) {
}

// FollowerStates holds information about all the followers in the raft cluster
// tracked by the leader.
type FollowerStates struct {
	l         sync.RWMutex
	followers map[string]*FollowerState
}

func NewFollowerStates() *FollowerStates {
	return &FollowerStates{followers: make(map[string]*FollowerState)}
}

func (s *FollowerStates) Update(req *EchoRequestUpdate) bool {
	s.l.Lock()
	defer s.l.Unlock()
	_, present := s.followers[req.NodeID]
	s.followers[req.NodeID] = &FollowerState{
		AppliedIndex:    req.AppliedIndex,
		LastHeartbeat:   time.Now(),
		LastTerm:        req.Term,
		IsDead:          &atomic.Bool{},
		DesiredSuffrage: req.DesiredSuffrage,
		Version:         req.SDKVersion,
		UpgradeVersion:  req.UpgradeVersion,
	}
	return !present
}

func (s *FollowerStates) Clear() {
	s.l.Lock()
	s.followers = make(map[string]*FollowerState)
	s.l.Unlock()
}

func (s *FollowerStates) Delete(nodeID string) {
	s.l.Lock()
	delete(s.followers, nodeID)
	s.l.Unlock()
}

func (s *FollowerStates) MinIndex() uint64 { return 0 }

func (s *FollowerStates) HaveFollower() bool {
	s.l.RLock()
	defer s.l.RUnlock()
	return len(s.followers) > 0
}

// Delegate is the autopilot delegate; a no-op on js/wasm.
type Delegate struct {
	*RaftBackend
}

func NewDelegate(b *RaftBackend) *Delegate { return &Delegate{RaftBackend: b} }

func (d *Delegate) AutopilotConfig() *autopilot.Config { return nil }

func NewReadableDuration(dur time.Duration) *ReadableDuration {
	d := ReadableDuration(dur)
	return &d
}

func (d *ReadableDuration) String() string          { return d.Duration().String() }
func (d *ReadableDuration) Duration() time.Duration { return time.Duration(*d) }

var _ = x509.Certificate{}
var _ = ecdsa.PrivateKey{}

// LeaderJoinInfo contains information required by a node to join itself as a
// follower to an existing raft cluster
type LeaderJoinInfo struct {
	// AutoJoin defines any cloud auto-join metadata. If supplied, Vault will
	// attempt to automatically discover peers in addition to what can be provided
	// via 'leader_api_addr'.
	AutoJoin string `json:"auto_join"`

	// AutoJoinScheme defines the optional URI protocol scheme for addresses
	// discovered via auto-join.
	AutoJoinScheme string `json:"auto_join_scheme"`

	// AutoJoinPort defines the optional port used for addressed discovered via
	// auto-join.
	AutoJoinPort uint `json:"auto_join_port"`

	// LeaderAPIAddr is the address of the leader node to connect to
	LeaderAPIAddr string `json:"leader_api_addr"`

	// LeaderCACert is the CA cert of the leader node
	LeaderCACert string `json:"leader_ca_cert"`

	// LeaderClientCert is the client certificate for the follower node to
	// establish client authentication during TLS
	LeaderClientCert string `json:"leader_client_cert"`

	// LeaderClientKey is the client key for the follower node to establish
	// client authentication during TLS.
	LeaderClientKey string `json:"leader_client_key"`

	// LeaderCACertFile is the path on disk to the the CA cert file of the
	// leader node. This should only be provided via Vault's configuration file.
	LeaderCACertFile string `json:"leader_ca_cert_file"`

	// LeaderClientCertFile is the path on disk to the client certificate file
	// for the follower node to establish client authentication during TLS. This
	// should only be provided via Vault's configuration file.
	LeaderClientCertFile string `json:"leader_client_cert_file"`

	// LeaderClientKeyFile is the path on disk to the client key file for the
	// follower node to establish client authentication during TLS. This should
	// only be provided via Vault's configuration file.
	LeaderClientKeyFile string `json:"leader_client_key_file"`

	// LeaderTLSServerName is the optional ServerName to expect in the leader's
	// certificate, instead of the host/IP we're actually connecting to.
	LeaderTLSServerName string `json:"leader_tls_servername"`

	// Retry indicates if the join process should automatically be retried
	Retry bool `json:"-"`

	// TLSConfig for the API client to use when communicating with the leader node
	TLSConfig *tls.Config `json:"-"`
}

// RaftServer has information about a server in the Raft configuration
type RaftServer struct {
	// NodeID is the name of the server
	NodeID string `json:"node_id"`

	// Address is the IP:port of the server, used for Raft communications
	Address string `json:"address"`

	// Leader is true if this server is the current cluster leader
	Leader bool `json:"leader"`

	// Protocol version is the raft protocol version used by the server
	ProtocolVersion string `json:"protocol_version"`

	// Voter is true if this server has a vote in the cluster. This might
	// be false if the server is staging and still coming online.
	Voter bool `json:"voter"`
}

// RaftConfigurationResponse is returned when querying for the current Raft
// configuration.
type RaftConfigurationResponse struct {
	// Servers has the list of servers in the Raft configuration.
	Servers []*RaftServer `json:"servers"`

	// Index has the Raft index of this configuration.
	Index uint64 `json:"index"`
}

// Peer defines the ID and Address for a given member of the raft cluster.
type Peer struct {
	ID       string `json:"id"`
	Address  string `json:"address"`
	Suffrage int    `json:"suffrage"`
}

// SetupOpts are used to pass options to the raft setup function.
type SetupOpts struct {
	// TLSKeyring is the keyring to use for the cluster traffic.
	TLSKeyring *TLSKeyring

	// ClusterListener is the cluster hook used to register the raft handler and
	// client with core's cluster listeners.
	ClusterListener cluster.ClusterHook

	// StartAsLeader is used to specify this node should start as leader and
	// bypass the leader election. This should be used with caution.
	StartAsLeader bool

	// RecoveryModeConfig is the configuration for the raft cluster in recovery
	// mode.
	RecoveryModeConfig *raft.Configuration
}

type CleanupDeadServersValue int

// AutopilotConfig is used for querying/setting the Autopilot configuration.
type AutopilotConfig struct {
	// CleanupDeadServers controls whether to remove dead servers from the Raft
	// peer list periodically or when a new server joins.
	CleanupDeadServers bool `mapstructure:"cleanup_dead_servers"`

	// CleanupDeadServersValue is used to shadow the CleanupDeadServers field in
	// storage. Having it as an int helps in knowing if the value was set explicitly
	// using the API or not.
	CleanupDeadServersValue CleanupDeadServersValue `mapstructure:"cleanup_dead_servers_value"`

	// LastContactThreshold is the limit on the amount of time a server can go
	// without leader contact before being considered unhealthy.
	LastContactThreshold time.Duration `mapstructure:"-"`

	// DeadServerLastContactThreshold is the limit on the amount of time a server
	// can go without leader contact before being considered failed. This takes
	// effect only when CleanupDeadServers is set.
	DeadServerLastContactThreshold time.Duration `mapstructure:"-"`

	// MaxTrailingLogs is the amount of entries in the Raft Log that a server can
	// be behind before being considered unhealthy.
	MaxTrailingLogs uint64 `mapstructure:"max_trailing_logs"`

	// MinQuorum sets the minimum number of servers allowed in a cluster before
	// autopilot can prune dead servers.
	MinQuorum uint `mapstructure:"min_quorum"`

	// ServerStabilizationTime is the minimum amount of time a server must be in a
	// stable, healthy state before it can be added to the cluster. Only applicable
	// with Raft protocol version 3 or higher.
	ServerStabilizationTime time.Duration `mapstructure:"-"`
}

// FollowerState represents the information about peer that the leader tracks.
type FollowerState struct {
	AppliedIndex    uint64
	LastHeartbeat   time.Time
	LastTerm        uint64
	IsDead          *atomic.Bool
	DesiredSuffrage string
	Version         string
	UpgradeVersion  string
}

// EchoRequestUpdate is here to avoid 1) the list of arguments to Update() getting huge 2) an import cycle on the vault package
type EchoRequestUpdate struct {
	NodeID          string
	AppliedIndex    uint64
	Term            uint64
	DesiredSuffrage string
	UpgradeVersion  string
	SDKVersion      string
}

// AutopilotState represents the health information retrieved from autopilot.
type AutopilotState struct {
	Healthy                    bool                        `json:"healthy" mapstructure:"healthy"`
	FailureTolerance           int                         `json:"failure_tolerance" mapstructure:"failure_tolerance"`
	Servers                    map[string]*AutopilotServer `json:"servers" mapstructure:"servers"`
	Leader                     string                      `json:"leader" mapstructure:"leader"`
	Voters                     []string                    `json:"voters" mapstructure:"voters"`
	NonVoters                  []string                    `json:"non_voters,omitempty" mapstructure:"non_voters,omitempty"`
	Upgrade                    *AutopilotUpgrade           `json:"upgrade_info,omitempty" mapstructure:"upgrade_info,omitempty"`
	OptimisticFailureTolerance int                         `json:"optimistic_failure_tolerance,omitempty" mapstructure:"optimistic_failure_tolerance,omitempty"`
}

// AutopilotServer represents the health information of individual server node
// retrieved from autopilot.
type AutopilotServer struct {
	ID             string            `json:"id" mapstructure:"id"`
	Name           string            `json:"name" mapstructure:"name"`
	Address        string            `json:"address" mapstructure:"address"`
	NodeStatus     string            `json:"node_status" mapstructure:"node_status"`
	LastContact    *ReadableDuration `json:"last_contact" mapstructure:"last_contact"`
	LastTerm       uint64            `json:"last_term" mapstructure:"last_term"`
	LastIndex      uint64            `json:"last_index" mapstructure:"last_index"`
	Healthy        bool              `json:"healthy" mapstructure:"healthy"`
	StableSince    time.Time         `json:"stable_since" mapstructure:"stable_since"`
	Status         string            `json:"status" mapstructure:"status"`
	Version        string            `json:"version" mapstructure:"version"`
	UpgradeVersion string            `json:"upgrade_version,omitempty" mapstructure:"upgrade_version,omitempty"`
	ReadReplica    bool              `json:"read_replica,omitempty" mapstructure:"read_replica,omitempty"`
	NodeType       string            `json:"node_type,omitempty" mapstructure:"node_type,omitempty"`
}

type AutopilotZone struct {
	Servers          []string `json:"servers,omitempty" mapstructure:"servers,omitempty"`
	Voters           []string `json:"voters,omitempty" mapstructure:"voters,omitempty"`
	FailureTolerance int      `json:"failure_tolerance,omitempty" mapstructure:"failure_tolerance,omitempty"`
}

type AutopilotUpgrade struct {
	Status                    string   `json:"status" mapstructure:"status"`
	TargetVersion             string   `json:"target_version,omitempty" mapstructure:"target_version,omitempty"`
	TargetVersionVoters       []string `json:"target_version_voters,omitempty" mapstructure:"target_version_voters,omitempty"`
	TargetVersionNonVoters    []string `json:"target_version_non_voters,omitempty" mapstructure:"target_version_non_voters,omitempty"`
	TargetVersionReadReplicas []string `json:"target_version_read_replicas,omitempty" mapstructure:"target_version_read_replicas,omitempty"`
	OtherVersionVoters        []string `json:"other_version_voters,omitempty" mapstructure:"other_version_voters,omitempty"`
	OtherVersionNonVoters     []string `json:"other_version_non_voters,omitempty" mapstructure:"other_version_non_voters,omitempty"`
	OtherVersionReadReplicas  []string `json:"other_version_read_replicas,omitempty" mapstructure:"other_version_read_replicas,omitempty"`
}

type AutopilotZoneUpgradeVersions struct {
	TargetVersionVoters    []string `json:"target_version_voters,omitempty" mapstructure:"target_version_voters,omitempty"`
	TargetVersionNonVoters []string `json:"target_version_non_voters,omitempty" mapstructure:"target_version_non_voters,omitempty"`
	OtherVersionVoters     []string `json:"other_version_voters,omitempty" mapstructure:"other_version_voters,omitempty"`
	OtherVersionNonVoters  []string `json:"other_version_non_voters,omitempty" mapstructure:"other_version_non_voters,omitempty"`
}

// ReadableDuration is a duration type that is serialized to JSON in human readable format.
type ReadableDuration time.Duration

// TLSKey is a single TLS keypair in the Keyring
type TLSKey struct {
	// ID is a unique identifier for this Key
	ID string `json:"id"`

	// KeyType defines the algorighm used to generate the private keys
	KeyType string `json:"key_type"`

	// AppliedIndex is the earliest known raft index that safely contains this
	// key.
	AppliedIndex uint64 `json:"applied_index"`

	// CertBytes is the marshaled certificate.
	CertBytes []byte `json:"cluster_cert"`

	// KeyParams is the marshaled private key.
	KeyParams *certutil.ClusterKeyParams `json:"cluster_key_params"`

	// CreatedTime is the time this key was generated. This value is useful in
	// determining when the next rotation should be.
	CreatedTime time.Time `json:"created_time"`

	parsedCert *x509.Certificate
	parsedKey  *ecdsa.PrivateKey
}

// TLSKeyring is the set of keys that raft uses for network communication.
// Only one key is used to dial at a time but both keys will be used to accept
// connections.
type TLSKeyring struct {
	// Keys is the set of available key pairs
	Keys []*TLSKey `json:"keys"`

	// AppliedIndex is the earliest known raft index that safely contains the
	// latest key in the keyring.
	AppliedIndex uint64 `json:"applied_index"`

	// Term is an incrementing identifier value used to quickly determine if two
	// states of the keyring are different.
	Term uint64 `json:"term"`

	// ActiveKeyID is the key ID to track the active key in the keyring. Only
	// the active key is used for dialing.
	ActiveKeyID string `json:"active_key_id"`
}

func (b *RaftBackend) Term() uint64             { return 0 }
func (b *RaftBackend) EffectiveVersion() string { return "" }

func (to *AutopilotConfig) Merge(from *AutopilotConfig) {
	if from == nil {
		return
	}
	if from.CleanupDeadServersValue != CleanupDeadServersUnset {
		to.CleanupDeadServers = from.CleanupDeadServersValue.Value()
	}
	if from.MinQuorum != 0 {
		to.MinQuorum = from.MinQuorum
	}
	if from.LastContactThreshold != 0 {
		to.LastContactThreshold = from.LastContactThreshold
	}
	if from.DeadServerLastContactThreshold != 0 {
		to.DeadServerLastContactThreshold = from.DeadServerLastContactThreshold
	}
	if from.MaxTrailingLogs != 0 {
		to.MaxTrailingLogs = from.MaxTrailingLogs
	}
	if from.ServerStabilizationTime != 0 {
		to.ServerStabilizationTime = from.ServerStabilizationTime
	}
}

// Clone returns a duplicate instance of AutopilotConfig with the exact same values.

func (ac *AutopilotConfig) Clone() *AutopilotConfig {
	if ac == nil {
		return nil
	}
	return &AutopilotConfig{
		CleanupDeadServers:             ac.CleanupDeadServers,
		LastContactThreshold:           ac.LastContactThreshold,
		DeadServerLastContactThreshold: ac.DeadServerLastContactThreshold,
		MaxTrailingLogs:                ac.MaxTrailingLogs,
		MinQuorum:                      ac.MinQuorum,
		ServerStabilizationTime:        ac.ServerStabilizationTime,
	}
}

// RaftLock is a placeholder; HA via raft is unavailable on js/wasm.
type RaftLock struct{}

func (l *RaftLock) Lock(stopCh <-chan struct{}) (<-chan struct{}, error) {
	return nil, ErrNotSupported
}
func (l *RaftLock) Unlock() error                { return nil }
func (l *RaftLock) Value() (bool, string, error) { return false, "", ErrNotSupported }

func (b *RaftBackend) AppliedReplicationIndex(_ context.Context) (string, error) {
	return "", ErrNotSupported
}
func (b *RaftBackend) BeginReadOnlyTx(ctx context.Context) (physical.Transaction, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) BeginTx(ctx context.Context) (physical.Transaction, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) CollectMetrics(sink *metricsutil.ClusterMetricSink) {}
func (b *RaftBackend) DemotePeer(ctx context.Context, peerID string) error {
	return ErrNotSupported
}
func (b *RaftBackend) FailGetInTxn() {}
func (b *RaftBackend) GetConfigurationOffline() (*RaftConfigurationResponse, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) GreaterEqualReplicationIndex(ctx context.Context, left string, right string) (bool, error) {
	return false, ErrNotSupported
}
func (b *RaftBackend) HAEnabled() bool                        { return false }
func (b *RaftBackend) JoinConfig() ([]*LeaderJoinInfo, error) { return nil, nil }
func (b *RaftBackend) LockWith(key, value string) (physical.Lock, error) {
	return nil, ErrNotSupported
}
func (b *RaftBackend) NonVoter() bool { return false }
func (b *RaftBackend) PromotePeer(ctx context.Context, peerID string) error {
	return ErrNotSupported
}
func (b *RaftBackend) SetFollowerStates(states *FollowerStates) {}
func (b *RaftBackend) SetTLSKeyring(keyring *TLSKeyring) error  { return ErrNotSupported }
func (b *RaftBackend) Snapshot(out io.Writer, access seal.Access) error {
	return ErrNotSupported
}
