package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
)

// clientAssertionCredential authenticates an application with assertions provided by a callback function.
type clientAssertionCredential struct {
	assertion, file string
	client          confidential.Client
	lastRead        time.Time
}

// clientAssertionCredentialOptions contains optional parameters for ClientAssertionCredential.
type clientAssertionCredentialOptions struct {
	azcore.ClientOptions
}

// newClientAssertionCredential constructs a clientAssertionCredential. Pass nil for options to accept defaults.
func newClientAssertionCredential(tenantID, clientID, authorityHost, file string, options *clientAssertionCredentialOptions) (*clientAssertionCredential, error) {
	c := &clientAssertionCredential{file: file}

	if options == nil {
		options = &clientAssertionCredentialOptions{}
	}

	cred := confidential.NewCredFromAssertionCallback(
		func(ctx context.Context, _ confidential.AssertionRequestOptions) (string, error) {
			return c.getAssertion(ctx)
		},
	)

	authority := fmt.Sprintf("%s%s/oauth2/token", authorityHost, tenantID)
	client, err := confidential.New(authority, clientID, cred,
		confidential.WithInstanceDiscovery(false), confidential.WithHTTPClient(createCustomHTTPClient(tenantID)))

	if err != nil {
		return nil, fmt.Errorf("failed to create confidential client: %w", err)
	}
	c.client = client

	return c, nil
}

// GetToken implements the TokenCredential interface
func (c *clientAssertionCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	// get the token from the confidential client
	token, err := c.client.AcquireTokenByCredential(ctx, opts.Scopes)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	return azcore.AccessToken{
		Token:     token.AccessToken,
		ExpiresOn: token.ExpiresOn,
	}, nil
}

// getAssertion reads the assertion from the file and returns it
// if the file has not been read in the last 5 minutes
func (c *clientAssertionCredential) getAssertion(context.Context) (string, error) {
	if now := time.Now(); c.lastRead.Add(5 * time.Minute).Before(now) {
		content, err := os.ReadFile(c.file)
		if err != nil {
			return "", err
		}
		c.assertion = string(content)
		c.lastRead = now
	}
	return c.assertion, nil
}

func createCustomHTTPClient(tenantID string) *http.Client {
	return &http.Client{
		Transport: &customHTTPClient{tenantID: tenantID},
	}
}

type customHTTPClient struct {
	tenantID string
}

func (c *customHTTPClient) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.String(), ".well-known/openid-configuration") {
		fmt.Println("requesting openid-configuration")
		resp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// read the response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		// set the authorization_endpoint in the original response

		type response struct {
			Issuer                           string   `json:"issuer"`
			JwksURI                          string   `json:"jwks_uri"`
			AuthorizationEndpoint            string   `json:"authorization_endpoint"`
			TokenEndpoint                    string   `json:"token_endpoint"`
			ResponseTypesSupported           []string `json:"response_types_supported"`
			SubjectTypesSupported            []string `json:"subject_types_supported"`
			IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
		}

		var r response
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		// TODO(aramase): use the authority host env var
		r.AuthorizationEndpoint = "https://krossota.monis.app/" + c.tenantID + "/oauth2/v2.0/token"
		r.TokenEndpoint = "https://krossota.monis.app/" + c.tenantID + "/oauth2/v2.0/token"

		body, err = json.Marshal(r)
		if err != nil {
			return nil, err
		}

		resp = &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          nil,
			ContentLength: int64(len(body)),
			Request:       req,
		}

		// set the response body
		resp.Body = io.NopCloser(bytes.NewReader(body))

		return resp, nil
	}

	return http.DefaultTransport.RoundTrip(req)
}
