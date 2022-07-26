package cloud

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azidentity "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/azure/cli"
	"github.com/microsoft/kiota/abstractions/go/authentication"
	kiotaauth "github.com/microsoft/kiota/authentication/go/azure"
	msgraphbetasdk "github.com/microsoftgraph/msgraph-beta-sdk-go"
	"github.com/microsoftgraph/msgraph-beta-sdk-go/models/microsoft/graph"
	"github.com/pkg/errors"
)

// ref: https://docs.microsoft.com/en-us/graph/migrate-azure-ad-graph-request-differences#basic-requests
var msGraphEndpoint = map[azure.Environment]string{
	azure.PublicCloud:       "https://graph.microsoft.com/",
	azure.USGovernmentCloud: "https://graph.microsoft.us/",
	azure.ChinaCloud:        "https://microsoftgraph.chinacloudapi.cn/",
	azure.GermanCloud:       "https://graph.microsoft.de/",
}

type Interface interface {
	CreateServicePrincipal(ctx context.Context, appID string, tags []string) (*graph.ServicePrincipal, error)
	CreateApplication(ctx context.Context, displayName string) (*graph.Application, error)
	DeleteServicePrincipal(ctx context.Context, objectID string) error
	DeleteApplication(ctx context.Context, objectID string) error
	GetServicePrincipal(ctx context.Context, displayName string) (*graph.ServicePrincipal, error)
	GetApplication(ctx context.Context, displayName string) (*graph.Application, error)

	// Role assignment methods
	CreateRoleAssignment(ctx context.Context, scope, roleName, principalID string) (authorization.RoleAssignment, error)
	DeleteRoleAssignment(ctx context.Context, roleAssignmentID string) (authorization.RoleAssignment, error)

	// Role definition methods
	GetRoleDefinitionIDByName(ctx context.Context, scope, roleName string) (authorization.RoleDefinition, error)

	// Federation methods
	AddFederatedCredential(ctx context.Context, objectID string, fic *graph.FederatedIdentityCredential) error
	GetFederatedCredential(ctx context.Context, objectID, issuer, subject string) (*graph.FederatedIdentityCredential, error)
	DeleteFederatedCredential(ctx context.Context, objectID, federatedCredentialID string) error
}

type AzureClient struct {
	environment    azure.Environment
	subscriptionID string

	graphServiceClient *msgraphbetasdk.GraphServiceClient

	roleAssignmentsClient *authorization.RoleAssignmentsClient
	roleDefinitionsClient *authorization.RoleDefinitionsClient
}

// NewAzureClientWithCLI creates an AzureClient configured from Azure CLI 2.0 for local development scenarios.
func NewAzureClientWithCLI(env azure.Environment, subscriptionID, tenantID string) (*AzureClient, error) {
	_, tenantID, err := getOAuthConfig(env, subscriptionID, tenantID)
	if err != nil {
		return nil, err
	}

	token, err := cli.GetTokenFromCLI(env.ResourceManagerEndpoint)
	if err != nil {
		return nil, err
	}

	adalToken, err := token.ToADALToken()
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create credential")
	}
	auth, err := kiotaauth.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{getGraphScope(env)})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create authentication provider")
	}

	return getClient(env, subscriptionID, tenantID, autorest.NewBearerAuthorizer(&adalToken), auth)
}

// NewAzureClientWithClientSecret returns an AzureClient via client_id and client_secret
func NewAzureClientWithClientSecret(env azure.Environment, subscriptionID, clientID, clientSecret, tenantID string) (*AzureClient, error) {
	oauthConfig, tenantID, err := getOAuthConfig(env, subscriptionID, tenantID)
	if err != nil {
		return nil, err
	}

	armSpt, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, clientSecret, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create credential")
	}
	auth, err := kiotaauth.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{getGraphScope(env)})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create authentication provider")
	}

	return getClient(env, subscriptionID, tenantID, autorest.NewBearerAuthorizer(armSpt), auth)
}

// NewAzureClientWithClientCertificateFile returns an AzureClient via client_id and jwt certificate assertion
func NewAzureClientWithClientCertificateFile(env azure.Environment, subscriptionID, clientID, tenantID, certificatePath, privateKeyPath string) (*AzureClient, error) {
	certificateData, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to read certificate")
	}

	block, _ := pem.Decode(certificateData)
	if block == nil {
		return nil, errors.New("Failed to decode pem block from certificate")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse certificate")
	}

	privateKey, err := parseRsaPrivateKey(privateKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse rsa private key")
	}

	return NewAzureClientWithClientCertificate(env, subscriptionID, clientID, tenantID, certificate, privateKey)
}

// NewAzureClientWithClientCertificate returns an AzureClient via client_id and jwt certificate assertion
func NewAzureClientWithClientCertificate(env azure.Environment, subscriptionID, clientID, tenantID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey) (*AzureClient, error) {
	oauthConfig, tenantID, err := getOAuthConfig(env, subscriptionID, tenantID)
	if err != nil {
		return nil, err
	}

	return newAzureClientWithCertificate(env, oauthConfig, subscriptionID, clientID, tenantID, certificate, privateKey)
}

// NewAzureClientWithClientCertificateExternalTenant returns an AzureClient via client_id and jwt certificate assertion against a 3rd party tenant
func NewAzureClientWithClientCertificateExternalTenant(env azure.Environment, subscriptionID, tenantID, clientID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey) (*AzureClient, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}

	return newAzureClientWithCertificate(env, oauthConfig, subscriptionID, clientID, tenantID, certificate, privateKey)
}

func getOAuthConfig(env azure.Environment, subscriptionID, tenantID string) (*adal.OAuthConfig, string, error) {
	oauthConfig, err := adal.NewOAuthConfig(env.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, "", err
	}

	return oauthConfig, tenantID, nil
}

func newAzureClientWithCertificate(env azure.Environment, oauthConfig *adal.OAuthConfig, subscriptionID, clientID, tenantID string, certificate *x509.Certificate, privateKey *rsa.PrivateKey) (*AzureClient, error) {
	if certificate == nil {
		return nil, errors.New("certificate should not be nil")
	}

	if privateKey == nil {
		return nil, errors.New("privateKey should not be nil")
	}

	armSpt, err := adal.NewServicePrincipalTokenFromCertificate(*oauthConfig, clientID, certificate, privateKey, env.ServiceManagementEndpoint)
	if err != nil {
		return nil, err
	}

	cred, err := azidentity.NewClientCertificateCredential(tenantID, clientID, []*x509.Certificate{certificate}, privateKey, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create credential")
	}
	auth, err := kiotaauth.NewAzureIdentityAuthenticationProviderWithScopes(cred, []string{getGraphScope(env)})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create authentication provider")
	}

	return getClient(env, subscriptionID, tenantID, autorest.NewBearerAuthorizer(armSpt), auth)
}

func getClient(env azure.Environment, subscriptionID, tenantID string, credential azcore.TokenCredential, auth authentication.AuthenticationProvider) (*AzureClient, error) {
	adapter, err := msgraphbetasdk.NewGraphRequestAdapter(auth)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request adapter")
	}

	// TODO(aramase) configure the cloud url for each client
	roleAssignmentsClient, err := authorization.NewRoleAssignmentsClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create role assignments client")
	}

	roleDefinitionsClient, err := authorization.NewRoleDefinitionsClient(credential, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create role definitions client")
	}

	azClient := &AzureClient{
		environment:    env,
		subscriptionID: subscriptionID,

		graphServiceClient: msgraphbetasdk.NewGraphServiceClient(adapter),

		roleAssignmentsClient: roleAssignmentsClient,
		roleDefinitionsClient: roleDefinitionsClient,
	}

	return azClient, nil
}

func parseRsaPrivateKey(path string) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(privateKeyData)
	if block == nil {
		return nil, errors.New("Failed to decode a pem block from private key")
	}

	privatePkcs1Key, errPkcs1 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errPkcs1 == nil {
		return privatePkcs1Key, nil
	}

	privatePkcs8Key, errPkcs8 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if errPkcs8 == nil {
		privatePkcs8RsaKey, ok := privatePkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("pkcs8 contained non-RSA key. Expected RSA key")
		}
		return privatePkcs8RsaKey, nil
	}

	return nil, errors.Errorf("failed to parse private key as Pkcs#1 or Pkcs#8. (%s). (%s)", errPkcs1, errPkcs8)
}

func getGraphScope(env azure.Environment) string {
	return fmt.Sprintf("%s.default", msGraphEndpoint[env])
}
