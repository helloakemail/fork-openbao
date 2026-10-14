// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

//go:build !js

package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	duoapi "github.com/duosecurity/duo_api_golang"
	"github.com/duosecurity/duo_api_golang/authapi"
	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
	"github.com/openbao/openbao/v2/internal/helper/identity/mfa"
)

func (c *Core) validateDuo(ctx context.Context, mfaFactors *MFAFactor, mConfig *mfa.Config, username, reqConnectionRemoteAddr string) error {
	duoConfig := mConfig.GetDuoConfig()
	if duoConfig == nil {
		return fmt.Errorf("failed to get Duo configuration for method %q", mConfig.Name)
	}

	var passcode string
	if mfaFactors != nil {
		passcode = mfaFactors.passcode
	}

	client := duoapi.NewDuoApi(
		duoConfig.IntegrationKey,
		duoConfig.SecretKey,
		duoConfig.APIHostname,
		duoConfig.PushInfo,
	)

	authClient := authapi.NewAuthApi(*client)
	check, err := authClient.Check()
	if err != nil {
		return err
	}
	if check == nil {
		//nolint:staticcheck // Duo is a proper name
		return errors.New("Duo api check returned nil, possibly bad integration key")
	}
	var message string
	var messageDetail string
	if check.Message != nil {
		message = *check.Message
	}
	if check.Message_Detail != nil {
		messageDetail = *check.Message_Detail
	}
	if check.Stat != "OK" {
		return fmt.Errorf("check against Duo failed; message (if given): %q; message detail (if given): %q", message, messageDetail)
	}

	preauth, err := authClient.Preauth(authapi.PreauthUsername(username), authapi.PreauthIpAddr(reqConnectionRemoteAddr))
	if err != nil {
		return fmt.Errorf("failed to perform Duo preauth: %w", err)
	}
	if preauth == nil {
		return errors.New("failed to perform Duo preauth")
	}
	if preauth.Stat != "OK" {
		return fmt.Errorf("failed to perform Duo preauth: %q - %q", *preauth.Message, *preauth.Message_Detail)
	}

	switch preauth.Response.Result {
	case "allow":
		return nil
	case "deny":
		return errors.New(preauth.Response.Status_Msg)
	case "enroll":
		return fmt.Errorf("%q - %q", preauth.Response.Status_Msg, preauth.Response.Enroll_Portal_Url)
	case "auth":
		break
	default:
		return fmt.Errorf("invalid response from Duo preauth: %q", preauth.Response.Result)
	}

	options := []func(*url.Values){}
	factor := "push"
	if passcode != "" {
		factor = "passcode"
		options = append(options, authapi.AuthPasscode(passcode))
	} else {
		options = append(options, authapi.AuthDevice("auto"))
		if duoConfig.PushInfo != "" {
			options = append(options, authapi.AuthPushinfo(duoConfig.PushInfo))
		}
	}

	options = append(options, authapi.AuthIpAddr(reqConnectionRemoteAddr))
	options = append(options, authapi.AuthUsername(username))
	options = append(options, authapi.AuthAsync())

	result, err := authClient.Auth(factor, options...)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Duo: %w", err)
	}
	if result.Stat != "OK" {
		return fmt.Errorf("failed to authenticate with Duo: %q - %q", *result.Message, *result.Message_Detail)
	}
	if result.Response.Txid == "" {
		return errors.New("failed to get transaction ID for Duo authentication")
	}

	for {
		// AuthStatus does the long polling until there is a status update. So
		// there is no need to wait for a second before we invoke this API.
		statusResult, err := authClient.AuthStatus(result.Response.Txid)
		if err != nil {
			return fmt.Errorf("failed to get authentication status from Duo: %w", err)
		}
		if statusResult == nil {
			return fmt.Errorf("failed to get authentication status from Duo: %w", err)
		}
		if statusResult.Stat != "OK" {
			return fmt.Errorf("failed to get authentication status from Duo: %q - %q", *statusResult.Message, *statusResult.Message_Detail)
		}

		switch statusResult.Response.Result {
		case "deny":
			return fmt.Errorf("duo authentication failed: %q", statusResult.Response.Status_Msg)
		case "allow":
			return nil
		}
		timer := time.NewTimer(time.Second)

		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("duo push verification operation canceled")
		case <-timer.C:
		}
	}
}

func (c *Core) validateOkta(ctx context.Context, mConfig *mfa.Config, username string) error {
	oktaConfig := mConfig.GetOktaConfig()
	if oktaConfig == nil {
		return fmt.Errorf("failed to get Okta configuration for method %q", mConfig.Name)
	}

	baseURL := oktaConfig.BaseURL
	if baseURL == "" {
		baseURL = "okta.com"
	}
	orgURL, err := url.Parse(fmt.Sprintf("https://%s.%s", oktaConfig.OrgName, baseURL))
	if err != nil {
		return err
	}

	ctx, client, err := okta.NewClient(
		ctx,
		okta.WithToken(oktaConfig.APIToken),
		okta.WithOrgUrl(orgURL.String()),
		// Do not use cache or polling MFA will not refresh
		okta.WithCache(false),
	)
	if err != nil {
		return fmt.Errorf("error creating client: %s", err)
	}

	filterField := "profile.login"
	if oktaConfig.PrimaryEmail {
		filterField = "profile.email"
	}
	filterQuery := fmt.Sprintf("%s eq %q", filterField, username)
	filter := query.NewQueryParams(query.WithFilter(filterQuery))

	users, _, err := client.User.ListUsers(ctx, filter)
	if err != nil {
		return err
	}
	switch {
	case len(users) == 0:
		return errors.New("no users found for e-mail address")
	case len(users) > 1:
		return errors.New("more than one user found for e-mail address")
	}

	user := users[0]

	factors, _, err := client.UserFactor.ListFactors(ctx, user.Id)
	if err != nil {
		return err
	}

	if len(factors) == 0 {
		return errors.New("no MFA factors found for user")
	}

	var factorFound bool
	var userFactor *okta.UserFactor
	for _, factor := range factors {
		if factor.IsUserFactorInstance() {
			userFactor = factor.(*okta.UserFactor)
			if userFactor.FactorType == "push" {
				factorFound = true
				break
			}
		}
	}

	if !factorFound {
		return errors.New("no push-type MFA factor found for user")
	}

	result, _, err := client.UserFactor.VerifyFactor(ctx, user.Id, userFactor.Id, okta.VerifyFactorRequest{}, userFactor, nil)
	if err != nil {
		return err
	}

	if result.FactorResult != "WAITING" {
		return fmt.Errorf("expected WAITING status for push status, got %q", result.FactorResult)
	}

	// Parse links to get polling link
	type linksObj struct {
		Poll struct {
			Href string `mapstructure:"href"`
		} `mapstructure:"poll"`
	}
	links := new(linksObj)
	if err := mapstructure.WeakDecode(result.Links, links); err != nil {
		return err
	}
	// Strip the org URL from the fully qualified poll URL
	url, err := url.Parse(strings.Replace(links.Poll.Href, orgURL.String(), "", 1))
	if err != nil {
		return err
	}

	for {
		// Okta provides an SDK method `GetFactorTransactionStatus` but does not provide the transaction id in
		// the VerifyFactor response. This code effectively reimplements that method.
		rq := client.CloneRequestExecutor()
		req, err := rq.WithAccept("application/json").WithContentType("application/json").NewRequest("GET", url.String(), nil)
		if err != nil {
			return err
		}
		var result *okta.VerifyUserFactorResponse
		_, err = rq.Do(ctx, req, &result)
		if err != nil {
			return err
		}

		switch result.FactorResult {
		case "WAITING":
		case "SUCCESS":
			return nil
		case "REJECTED":
			return errors.New("push verification explicitly rejected")
		case "TIMEOUT":
			return errors.New("push verification timed out")
		default:
			return errors.New("unknown status code")
		}
		timer := time.NewTimer(time.Second)

		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("push verification operation canceled")
		case <-timer.C:
		}
	}
}

func (c *Core) validatePingID(ctx context.Context, mConfig *mfa.Config, username string) error {
	pingConfig := mConfig.GetPingIDConfig()
	if pingConfig == nil {
		return fmt.Errorf("failed to get PingID configuration for method %q", mConfig.Name)
	}

	signingKey, err := base64.StdEncoding.DecodeString(pingConfig.UseBase64Key)
	if err != nil {
		return fmt.Errorf("failed decoding pingid signing key: %w", err)
	}

	client := cleanhttp.DefaultClient()

	createRequest := func(reqPath string, reqBody map[string]any) (*http.Request, error) {
		// Construct the token
		token := &jwt.Token{
			Method: jwt.SigningMethodHS256,
			Header: map[string]any{
				"alg":       "HS256",
				"org_alias": pingConfig.OrgAlias,
				"token":     pingConfig.Token,
			},
			Claims: jwt.MapClaims{
				"reqHeader": map[string]any{
					"locale":    "en",
					"orgAlias":  pingConfig.OrgAlias,
					"secretKey": pingConfig.Token,
					"timestamp": time.Now().Format("2006-01-02  15:04:05.000"),
					"version":   "4.9",
				},
				"reqBody": reqBody,
			},
		}
		signedToken, err := token.SignedString(signingKey)
		if err != nil {
			return nil, fmt.Errorf("failed signing pingid request token: %w", err)
		}

		// Construct the URL
		if !strings.HasPrefix(reqPath, "/") {
			reqPath = "/" + reqPath
		}
		reqURL, err := url.Parse(pingConfig.IDPURL + reqPath)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pingid request url: %w", err)
		}

		// Construct the request; WithContext is done here since it's a shallow
		// copy
		req := &http.Request{}
		req = req.WithContext(ctx)
		req.Method = "POST"
		req.URL = reqURL
		req.Body = io.NopCloser(bytes.NewBufferString(signedToken))
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	}

	do := func(req *http.Request) (*jwt.Token, error) {
		// Run the request and fetch the response
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp == nil {
			return nil, errors.New("nil response from pingid")
		}
		if resp.Body == nil {
			return nil, errors.New("nil body in pingid response")
		}
		bodyBytes := bytes.NewBuffer(nil)
		_, err = bodyBytes.ReadFrom(resp.Body)
		resp.Body.Close() //nolint:errcheck
		if err != nil {
			return nil, fmt.Errorf("error reading pingid response: %w", err)
		}

		// Parse the body, which is a JWT. Ensure that it's using HMAC signing
		// and return the signing key in the func for validation
		token, err := jwt.Parse(bodyBytes.String(), func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %q from pingid response", token.Header["alg"])
			}
			return signingKey, nil
		})
		if err != nil {
			return nil, fmt.Errorf("error parsing pingid response: %w", err)
		}

		// Check if parameters are as expected
		if _, ok := token.Header["token"]; !ok {
			return nil, fmt.Errorf("%q header not found", "token")
		}
		if headerTokenStr, ok := token.Header["token"].(string); !ok || headerTokenStr != pingConfig.Token {
			return nil, errors.New("invalid token in ping response")
		}

		// validate org alias
		// This was originally 'org_alias', but it appears to now be returned as 'orgAlias'. Official
		// Ping docs are sparse on the header details. We now prefer orgAlias but will still handle
		// org_alias.
		oa := token.Header["orgAlias"]
		if oa == nil {
			if oa = token.Header["org_alias"]; oa == nil {
				return nil, errors.New("neither orgAlias nor org_alias headers were found")
			}
		}

		if headerOrgAliasStr, ok := oa.(string); !ok || headerOrgAliasStr != pingConfig.OrgAlias {
			return nil, errors.New("invalid org_alias in ping response")
		}
		return token, nil
	}

	type deviceDetails struct {
		PushEnabled bool  `mapstructure:"pushEnabled"`
		DeviceID    int64 `mapstructure:"deviceId"`
	}

	type respBody struct {
		SessionID   string          `mapstructure:"sessionId"`
		ErrorID     int64           `mapstructure:"errorId"`
		ErrorMsg    string          `mapstructure:"errorMsg"`
		UserDevices []deviceDetails `mapstructure:"userDevices"`
	}

	type apiResponse struct {
		ResponseBody respBody `mapstructure:"responseBody"`
	}

	/*
		// Normally we don't leave in commented code, however:
		// Explicitly setting the device ID didn't work even when the device was
		// push enabled (said the application was not installed on the device), so
		// instead trigger default behavior, which does work, even when there's
		// only one device and the deviceid matched :-/
		// We're leaving this here because if we support other types we'll likely
		// still need it, and if we get device ID selection working we'll want it.

		req, err := createRequest("rest/4/startauthentication/do", map[string]any{
			"spAlias":  "web",
			"userName": username,
		})
		if err != nil {
			return err
		}
		token, err := do(req)
		if err != nil {
			return err
		}

		// We get back a map from the JWT library so use mapstructure
		var startResp apiResponse
		err = mapstructure.Decode(token.Claims, &startResp)
		if err != nil {
			return err
		}

		// Look for at least one push-enabled method
		body := startResp.ResponseBody
		var foundPush bool
		switch {
		case body.ErrorID != 30007:
			return errors.New("only pingid push authentication is currently supported")

		case len(body.UserDevices) == 0:
			return errors.New("no user mfa devices returned from pingid")

		default:
			for _, dev := range body.UserDevices {
				if dev.PushEnabled {
					foundPush = true
					break
				}
			}

			if !foundPush {
				return errors.New("no push enabled device id found from pingid")
			}
		}
	*/
	req, err := createRequest("rest/4/authonline/do", map[string]any{
		"spAlias":  "web",
		"userName": username,
		"authType": "CONFIRM",
	})
	if err != nil {
		return err
	}
	token, err := do(req)
	if err != nil {
		return err
	}

	// Ensure a success response
	var authResp apiResponse
	err = mapstructure.Decode(token.Claims, &authResp)
	if err != nil {
		return err
	}

	if authResp.ResponseBody.ErrorID != 200 {
		return errors.New(authResp.ResponseBody.ErrorMsg)
	}

	return nil
}
