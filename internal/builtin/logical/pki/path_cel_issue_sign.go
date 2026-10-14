// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	celgo "cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"github.com/openbao/openbao/sdk/v2/framework"
	celhelper "github.com/openbao/openbao/sdk/v2/helper/cel"
	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

// The CEL-role issue/sign handlers live in this file so the js/wasm build,
// which excludes the CEL engine, can replace them (see path_cel_js.go).

func (b *backend) getCelEvalConfig(useCSR bool) *celhelper.EvalConfig {
	envOptions := []celgo.EnvOption{
		celgo.Variable("request", types.NewMapType(types.StringType, types.DynType)),
		celgo.Variable("now", types.TimestampType),
		celgo.Variable("use_csr", types.BoolType),
		celgo.Types(
			&CertTemplate{},
			&ValidationOutput{},
		),
	}

	if useCSR {
		envOptions = append(envOptions,
			celgo.Variable("parsed_csr",
				types.NewMapType(
					types.StringType,
					types.DynType,
				)))
	}

	return &celhelper.EvalConfig{
		Container:     "openbao.pki",
		WithExtLib:    true,
		WithEmail:     true,
		WithIdentity:  true,
		WithJSON:      true,
		CustomOptions: envOptions,
	}
}

func (b *backend) pathCelIssueSignCert(ctx context.Context, req *logical.Request, data *framework.FieldData, useCSR bool) (*logical.Response, error) {
	celRole, err := b.fetchAndValidateCelRole(ctx, req, data)
	if err != nil {
		return nil, err
	}

	cfg := b.getCelEvalConfig(useCSR)
	// Initialize the evaluation context for CEL expressions with the raw request data.
	// The "request" key allows CEL expressions to access and evaluate against input fields.
	// Additional variables and evaluated results will be added dynamically during processing.
	evaluationData := map[string]any{
		"use_csr": useCSR,
		"request": data.Raw,
		"now":     time.Now(),
	}

	// Parse then add the CSR to the evaluationData
	if useCSR {
		var parsedCsr map[string]any
		if useCSR {
			csrPEM, ok := data.GetOk("csr")
			if ok {
				// Convert CSR to a structured map
				parsedCsr, err = csrToMap(csrPEM.(string))
				if err != nil {
					return nil, fmt.Errorf("failed to parse CSR: %w", err)
				}
			}
		}

		evaluationData["parsed_csr"] = parsedCsr
	}

	// Evaluate MainProgram
	result, err := celRole.Program.Evaluate(ctx, cfg, evaluationData)
	if err != nil {
		return nil, fmt.Errorf("error evaluating mainProgram: %w", err)
	}

	validationOutput := new(ValidationOutput)
	switch v := result.Value().(type) {
	case *dynamicpb.Message:
		// The CEL program succeeded.

		// Marshal the dynamic message to wire-format bytes.
		bytes, err := proto.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal dynamic message: %w", err)
		}

		// Unmarshal into CertTemplate struct.
		if err := proto.Unmarshal(bytes, validationOutput); err != nil {
			return nil, fmt.Errorf("unmarshal into CertTemplate: %w", err)
		}

	case string:
		// The CEL program decided the request is invalid and returned a human-readable error string.
		return nil, errors.New(v)

	case bool:
		// The CEL program decided the request is invalid and returned a bool.
		return nil, errors.New("request denied")

	default:
		// Any other type is unexpected and indicates an error in MainProgram's policy.
		return nil, fmt.Errorf("unexpected mainProgram result type %T", v)
	}

	// Translate CertTemplate to *x509.Certificate struct.
	cert, err := CertProtoToX509(validationOutput.Template)
	if err != nil {
		return nil, err
	}

	// Fetch issuer information
	signingBundle, _, err := b.fetchCaSigningBundle(ctx, req, data, validationOutput.IssuerRef)
	if err != nil {
		return nil, err
	}

	// Ensure both TTL and notAfter are not provided together
	rawTTL := data.Get("ttl")
	rawNotAfter := data.Get("not_after")

	if rawTTL != 0 && rawNotAfter != "" {
		return nil, errutil.UserError{Err: "Either ttl or not_after should be provided. Both should not be provided in the same request."}
	}

	var (
		parsedBundle *certutil.ParsedCertBundle
		parseErr     error
	)

	// Move validated data into evaluationData for use by certutil. We use
	// the output copies to ensure they've been validated and any CEL-created
	// defaults applied, rather than overwriting data.Raw and potentially
	// using unsanitized values.
	signatureBits := int(validationOutput.SignatureBits)
	usePSS := validationOutput.UsePss
	if !useCSR {
		keyType := validationOutput.KeyType
		if keyType == "" {
			// Default to RSA
			keyType = "rsa"
		}

		keyBits := int(validationOutput.KeyBits)

		keyBits, err = certutil.ValidateDefaultOrValueKeyTypeLength(keyType, keyBits)
		if err != nil {
			return nil, fmt.Errorf("invalid cel response for key type, key bits, or signature bits: %w", err)
		}

		evaluationData["key_type"] = keyType
		evaluationData["key_bits"] = keyBits
		evaluationData["signature_bits"] = signatureBits
		evaluationData["use_pss"] = usePSS
	} else {
		signingKeyType := string(signingBundle.PrivateKeyType)
		if err := certutil.ValidateSignatureLength(signingKeyType, signatureBits); err != nil {
			return nil, err
		}

		evaluationData["signature_bits"] = signatureBits
		evaluationData["use_pss"] = usePSS
		evaluationData["subject_key_id"] = validationOutput.SubjectKeyId
	}

	if !useCSR {
		parsedBundle, parseErr = generateCELCert(evaluationData, signingBundle, cert, rand.Reader)
	} else {
		raw := data.Get("csr").(string)

		// convert string → []byte
		csrBytes := []byte(raw)

		pemBlock, _ := pem.Decode(csrBytes)
		if pemBlock == nil {
			return nil, errutil.UserError{Err: "csr contains no data"}
		}

		csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return nil, errutil.UserError{Err: fmt.Sprintf("certificate request could not be parsed: %v", err)}
		}

		parsedBundle, parseErr = signCELCert(evaluationData, signingBundle, cert, csr)
	}
	if parseErr != nil {
		switch parseErr.(type) {
		case errutil.UserError:
			return logical.ErrorResponse(parseErr.Error()), nil
		case errutil.InternalError:
			return nil, parseErr
		default:
			return nil, fmt.Errorf("error signing/generating certificate: %w", parseErr)
		}
	}

	signingCB, err := signingBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw signing bundle to cert bundle: %w", err)
	}

	cb, err := parsedBundle.ToCertBundle()
	if err != nil {
		return nil, fmt.Errorf("error converting raw cert bundle to cert bundle: %w", err)
	}

	caChainGen := newCaChainOutput(parsedBundle, data)

	respData := map[string]any{
		"certificate":      cb.Certificate,
		"not_before":       int64(parsedBundle.Certificate.NotBefore.Unix()),
		"expiration":       int64(parsedBundle.Certificate.NotAfter.Unix()),
		"serial_number":    cb.SerialNumber,
		"issuing_ca":       signingCB.Certificate,
		"private_key":      cb.PrivateKey,
		"private_key_type": cb.PrivateKeyType,
	}

	if caChainGen.containsChain() {
		respData["ca_chain"] = caChainGen.pemEncodedChain()
	}

	// Generate Response
	var resp *logical.Response
	if validationOutput.GenerateLease {
		// Lease-Managed Certificate
		resp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]any{
				"serial_number": cb.SerialNumber,
			},
		)
		resp.Secret.TTL = time.Until(parsedBundle.Certificate.NotAfter)
	} else {
		// Non-Leased Certificate
		resp = &logical.Response{
			Data: respData,
		}
	}

	if !validationOutput.NoStore {
		key := "certs/" + normalizeSerial(cb.SerialNumber)
		certsCounted := b.certsCounted.Load()
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   key,
			Value: parsedBundle.CertificateBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to store certificate locally: %w", err)
		}
		b.ifCountEnabledIncrementTotalCertificatesCount(certsCounted, key)
	}

	for _, warning := range validationOutput.Warnings {
		if len(warning) > 0 {
			resp.AddWarning(warning)
		}
	}

	return resp, nil
}

func (b *backend) fetchAndValidateCelRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*CELRoleEntry, error) {
	roleName, ok := data.GetOk("role")
	if !ok || roleName.(string) == "" {
		return nil, fmt.Errorf("missing CEL role name")
	}

	celRole, err := b.getCelRole(ctx, req.Storage, roleName.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch CEL role: %w", err)
	}
	if celRole == nil {
		return nil, fmt.Errorf("CEL role not found")
	}

	return celRole, nil
}
