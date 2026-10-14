// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build acceptance

// Package acceptance is a black-box API suite for the Worker build of
// OpenBao. It only talks HTTP through the api client, so the same tests run
// against a native server and against the wasm Worker under workerd or on
// Cloudflare. It assumes an auto-seal (static) server that may or may not be
// initialised yet.
//
//	BAO_ADDR=http://127.0.0.1:8787 BAO_ACCEPT_PG_URL=postgres://bao:bao@127.0.0.1:5432/bao?sslmode=disable \
//	  go test -tags acceptance -count=1 -v ./wasm/acceptance
//
// Set BAO_TOKEN to reuse an already-initialised server; otherwise the suite
// initialises it and prints the root token.
package acceptance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
)

func client(t *testing.T) *api.Client {
	t.Helper()
	addr := os.Getenv("BAO_ADDR")
	if addr == "" {
		t.Skip("BAO_ADDR not set")
	}
	cfg := api.DefaultConfig()
	cfg.Address = addr
	cfg.Timeout = 120 * time.Second
	c, err := api.NewClient(cfg)
	require.NoError(t, err)
	return c
}

// rootClient returns a client with a root token, initialising the server on
// first use. The token is cached in the process so every test shares it.
var cachedRoot string

func rootClient(t *testing.T) *api.Client {
	t.Helper()
	c := client(t)
	if cachedRoot == "" {
		cachedRoot = os.Getenv("BAO_TOKEN")
	}
	if cachedRoot == "" {
		st, err := c.Sys().InitStatus()
		require.NoError(t, err, "init status")
		if st {
			t.Fatal("server already initialised; pass BAO_TOKEN")
		}
		resp, err := c.Sys().Init(&api.InitRequest{RecoveryShares: 1, RecoveryThreshold: 1})
		require.NoError(t, err, "init")
		cachedRoot = resp.RootToken
		fmt.Fprintf(os.Stderr, "initialised: root token %s recovery key %s\n", resp.RootToken, resp.RecoveryKeysB64[0])
	}
	c.SetToken(cachedRoot)
	// Auto-seal servers unseal themselves; give a cold Worker a moment.
	require.Eventually(t, func() bool {
		h, err := c.Sys().Health()
		return err == nil && !h.Sealed && h.Initialized
	}, 60*time.Second, 500*time.Millisecond, "server did not become unsealed")
	return c
}

func TestHealth(t *testing.T) {
	c := rootClient(t)
	h, err := c.Sys().Health()
	require.NoError(t, err)
	require.True(t, h.Initialized)
	require.False(t, h.Sealed)
	require.False(t, h.Standby)
	t.Logf("version %s", h.Version)
}

func TestKV(t *testing.T) {
	c := rootClient(t)
	mount := "accept-kv"
	_ = c.Sys().Unmount(mount)
	require.NoError(t, c.Sys().Mount(mount, &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}))
	kv := c.KVv2(mount)
	for i := 0; i < 20; i++ {
		_, err := kv.Put(t.Context(), fmt.Sprintf("app/s%d", i), map[string]any{"k": fmt.Sprintf("v%d", i), "n": i})
		require.NoError(t, err)
	}
	s, err := kv.Get(t.Context(), "app/s7")
	require.NoError(t, err)
	require.Equal(t, "v7", s.Data["k"])
	_, err = kv.Put(t.Context(), "app/s7", map[string]any{"k": "v7b"})
	require.NoError(t, err)
	v1, err := kv.GetVersion(t.Context(), "app/s7", 1)
	require.NoError(t, err)
	require.Equal(t, "v7", v1.Data["k"])
	list, err := c.Logical().List(mount + "/metadata/app")
	require.NoError(t, err)
	require.Len(t, list.Data["keys"], 20)
	require.NoError(t, kv.Delete(t.Context(), "app/s7"))
	s, err = kv.Get(t.Context(), "app/s7")
	if err == nil {
		require.Nil(t, s.Data, "soft-deleted version must have no data")
		require.NotZero(t, s.VersionMetadata.DeletionTime)
	}
	require.NoError(t, c.Sys().Unmount(mount))
}

func TestPoliciesAndTokens(t *testing.T) {
	c := rootClient(t)
	require.NoError(t, c.Sys().PutPolicy("accept-ro", `path "secret/data/accept/*" { capabilities = ["read"] }`))
	pols, err := c.Sys().ListPolicies()
	require.NoError(t, err)
	require.Contains(t, pols, "accept-ro")
	tok, err := c.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"accept-ro"}, TTL: "1h"})
	require.NoError(t, err)
	look, err := c.Auth().Token().Lookup(tok.Auth.ClientToken)
	require.NoError(t, err)
	require.Contains(t, look.Data["policies"], "accept-ro")
	limited := client(t)
	limited.SetToken(tok.Auth.ClientToken)
	_, err = limited.Sys().ListPolicies()
	require.Error(t, err, "limited token must not list policies")
	require.NoError(t, c.Auth().Token().RevokeTree(tok.Auth.ClientToken))
	_, err = c.Auth().Token().Lookup(tok.Auth.ClientToken)
	require.Error(t, err)
	require.NoError(t, c.Sys().DeletePolicy("accept-ro"))
}

func TestUserpassAndAppRole(t *testing.T) {
	c := rootClient(t)
	_ = c.Sys().DisableAuth("accept-up")
	require.NoError(t, c.Sys().EnableAuthWithOptions("accept-up", &api.EnableAuthOptions{Type: "userpass"}))
	_, err := c.Logical().Write("auth/accept-up/users/alice", map[string]any{"password": "pw", "policies": "default"})
	require.NoError(t, err)
	anon := client(t)
	sec, err := anon.Logical().Write("auth/accept-up/login/alice", map[string]any{"password": "pw"})
	require.NoError(t, err)
	require.NotEmpty(t, sec.Auth.ClientToken)
	_, err = anon.Logical().Write("auth/accept-up/login/alice", map[string]any{"password": "wrong"})
	require.Error(t, err)
	require.NoError(t, c.Sys().DisableAuth("accept-up"))

	_ = c.Sys().DisableAuth("accept-ar")
	require.NoError(t, c.Sys().EnableAuthWithOptions("accept-ar", &api.EnableAuthOptions{Type: "approle"}))
	_, err = c.Logical().Write("auth/accept-ar/role/svc", map[string]any{"token_policies": "default", "token_ttl": "10m"})
	require.NoError(t, err)
	rid, err := c.Logical().Read("auth/accept-ar/role/svc/role-id")
	require.NoError(t, err)
	sid, err := c.Logical().Write("auth/accept-ar/role/svc/secret-id", nil)
	require.NoError(t, err)
	sec, err = anon.Logical().Write("auth/accept-ar/login", map[string]any{"role_id": rid.Data["role_id"], "secret_id": sid.Data["secret_id"]})
	require.NoError(t, err)
	require.NotEmpty(t, sec.Auth.ClientToken)
	require.NoError(t, c.Sys().DisableAuth("accept-ar"))
}

func TestJWTAuth(t *testing.T) {
	c := rootClient(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	_ = c.Sys().DisableAuth("accept-jwt")
	require.NoError(t, c.Sys().EnableAuthWithOptions("accept-jwt", &api.EnableAuthOptions{Type: "jwt"}))
	_, err = c.Logical().Write("auth/accept-jwt/config", map[string]any{"jwt_validation_pubkeys": pub})
	require.NoError(t, err)
	_, err = c.Logical().Write("auth/accept-jwt/role/ci", map[string]any{
		"role_type": "jwt", "user_claim": "sub", "bound_audiences": "openbao-accept", "token_policies": "default", "token_ttl": "5m",
	})
	require.NoError(t, err)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	require.NoError(t, err)
	now := time.Now()
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject: "alice", Audience: jwt.Audience{"openbao-accept"},
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute)), NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
	}).Serialize()
	require.NoError(t, err)
	anon := client(t)
	sec, err := anon.Logical().Write("auth/accept-jwt/login", map[string]any{"role": "ci", "jwt": raw})
	require.NoError(t, err)
	require.NotEmpty(t, sec.Auth.ClientToken)
	require.Equal(t, "ci", sec.Auth.Metadata["role"])
	require.NoError(t, c.Sys().DisableAuth("accept-jwt"))
}

func TestTransit(t *testing.T) {
	c := rootClient(t)
	_ = c.Sys().Unmount("accept-transit")
	require.NoError(t, c.Sys().Mount("accept-transit", &api.MountInput{Type: "transit"}))
	_, err := c.Logical().Write("accept-transit/keys/k1", map[string]any{"type": "aes256-gcm96"})
	require.NoError(t, err)
	pt := base64.StdEncoding.EncodeToString([]byte("hello worker"))
	enc, err := c.Logical().Write("accept-transit/encrypt/k1", map[string]any{"plaintext": pt})
	require.NoError(t, err)
	_, err = c.Logical().Write("accept-transit/keys/k1/rotate", nil)
	require.NoError(t, err)
	dec, err := c.Logical().Write("accept-transit/decrypt/k1", map[string]any{"ciphertext": enc.Data["ciphertext"]})
	require.NoError(t, err)
	require.Equal(t, pt, dec.Data["plaintext"])
	rew, err := c.Logical().Write("accept-transit/rewrap/k1", map[string]any{"ciphertext": enc.Data["ciphertext"]})
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(rew.Data["ciphertext"].(string), "vault:v2:"))
	require.NoError(t, c.Sys().Unmount("accept-transit"))
}

func TestPKI(t *testing.T) {
	c := rootClient(t)
	_ = c.Sys().Unmount("accept-pki")
	require.NoError(t, c.Sys().Mount("accept-pki", &api.MountInput{Type: "pki", Config: api.MountConfigInput{MaxLeaseTTL: "87600h"}}))
	root, err := c.Logical().Write("accept-pki/root/generate/internal", map[string]any{"common_name": "accept root", "ttl": "8760h", "key_type": "ec", "key_bits": 256})
	require.NoError(t, err)
	require.Contains(t, root.Data["certificate"], "BEGIN CERTIFICATE")
	_, err = c.Logical().Write("accept-pki/roles/web", map[string]any{"allowed_domains": "example.test", "allow_subdomains": true, "max_ttl": "72h", "key_type": "ec", "key_bits": 256})
	require.NoError(t, err)
	leaf, err := c.Logical().Write("accept-pki/issue/web", map[string]any{"common_name": "api.example.test", "ttl": "1h"})
	require.NoError(t, err)
	require.Contains(t, leaf.Data["certificate"], "BEGIN CERTIFICATE")
	_, err = c.Logical().Write("accept-pki/revoke", map[string]any{"serial_number": leaf.Data["serial_number"]})
	require.NoError(t, err)
	crl, err := c.Logical().ReadRaw("accept-pki/crl/pem")
	require.NoError(t, err)
	crl.Body.Close()
	require.Equal(t, 200, crl.StatusCode)
	require.NoError(t, c.Sys().Unmount("accept-pki"))
}

func TestDatabaseEngine(t *testing.T) {
	c := rootClient(t)
	pg := os.Getenv("BAO_ACCEPT_PG_URL")
	if pg == "" {
		t.Skip("BAO_ACCEPT_PG_URL not set")
	}
	_ = c.Sys().Unmount("accept-db")
	require.NoError(t, c.Sys().Mount("accept-db", &api.MountInput{Type: "database"}))
	_, err := c.Logical().Write("accept-db/config/pg", map[string]any{
		"plugin_name": "postgresql-database-plugin", "allowed_roles": "app", "connection_url": pg,
	})
	require.NoError(t, err)
	_, err = c.Logical().Write("accept-db/roles/app", map[string]any{
		"db_name": "pg", "default_ttl": "1h", "max_ttl": "24h",
		"creation_statements": `CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";`,
	})
	require.NoError(t, err)
	creds, err := c.Logical().Read("accept-db/creds/app")
	require.NoError(t, err)
	require.NotEmpty(t, creds.Data["username"])
	require.NotEmpty(t, creds.LeaseID)
	_, err = c.Sys().Renew(creds.LeaseID, 600)
	require.NoError(t, err)
	require.NoError(t, c.Sys().Revoke(creds.LeaseID))
	require.NoError(t, c.Sys().Unmount("accept-db"))
}

func TestLeasesAndTTL(t *testing.T) {
	c := rootClient(t)
	tok, err := c.Auth().Token().Create(&api.TokenCreateRequest{Policies: []string{"default"}, TTL: "2s", Renewable: new(bool)})
	require.NoError(t, err)
	short := client(t)
	short.SetToken(tok.Auth.ClientToken)
	_, err = short.Auth().Token().LookupSelf()
	require.NoError(t, err)
	time.Sleep(3 * time.Second)
	_, err = short.Auth().Token().LookupSelf()
	require.Error(t, err, "expired token must be rejected")
}
