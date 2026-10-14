// Copyright (c) 2025 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

//go:build js

package pki

import (
	"context"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// The js/wasm build excludes the CEL engine (cel-go, antlr) to keep the
// binary small, so CEL roles (path_cel.go, path_cel_issue_sign.go) are not
// available. The cel/ paths stay registered and answer with a clear error;
// classic roles, issue/ and sign/ are unaffected.

const celUnsupportedMsg = "CEL is not supported on this build"

func celUnsupported(context.Context, *logical.Request, *framework.FieldData) (*logical.Response, error) {
	return logical.ErrorResponse(celUnsupportedMsg), nil
}

func celUnsupportedPath(pattern string, fields []string, ops ...logical.Operation) *framework.Path {
	p := &framework.Path{
		Pattern:         pattern,
		Fields:          map[string]*framework.FieldSchema{},
		Operations:      map[logical.Operation]framework.OperationHandler{},
		HelpSynopsis:    celUnsupportedMsg,
		HelpDescription: celUnsupportedMsg,
	}
	for _, f := range fields {
		p.Fields[f] = &framework.FieldSchema{Type: framework.TypeString}
	}
	for _, op := range ops {
		p.Operations[op] = &framework.PathOperation{Callback: celUnsupported}
	}
	return p
}

func pathListCelRoles(*backend) *framework.Path {
	return celUnsupportedPath("cel/roles/?$", nil, logical.ListOperation)
}

func pathCelRoles(*backend) *framework.Path {
	return celUnsupportedPath("cel/roles/"+framework.GenericNameRegex("name"), []string{"name"},
		logical.ReadOperation, logical.CreateOperation, logical.UpdateOperation,
		logical.PatchOperation, logical.DeleteOperation)
}

// pathCelIssueSignCert backs cel/issue/:role and cel/sign/:role, whose path
// definitions are shared with the native build.
func (b *backend) pathCelIssueSignCert(context.Context, *logical.Request, *framework.FieldData, bool) (*logical.Response, error) {
	return logical.ErrorResponse(celUnsupportedMsg), nil
}
