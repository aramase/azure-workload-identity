package cloud

import (
	"context"
	"fmt"

	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// GetRoleDefinitionIDByName returns the role definition ID for the given role name.
func (c *AzureClient) GetRoleDefinitionIDByName(ctx context.Context, scope, roleName string) (authorization.RoleDefinition, error) {
	log.Debugf("Get role definition ID by name=%s", roleName)

	filter := getRoleNameFilter(roleName)
	opts := &authorization.RoleDefinitionsClientListOptions{
		Filter: &filter,
	}
	pager := c.roleDefinitionsClient.NewListPager(scope, opts)
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return authorization.RoleDefinition{}, errors.Wrap(err, "failed to list role definitions")
		}
		for _, r := range nextResult.Value {
			return *r, nil
		}
	}

	return authorization.RoleDefinition{}, errors.Errorf("role definition %s not found", roleName)
}

// getRoleNameFilter returns a filter string for the given role name.
// Supported filters are either roleName eq '{value}' or type eq 'BuiltInRole|CustomRole'."
func getRoleNameFilter(roleName string) string {
	return fmt.Sprintf("roleName eq '%s'", roleName)
}
