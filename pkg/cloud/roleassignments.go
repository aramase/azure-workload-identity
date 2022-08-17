package cloud

import (
	"context"
	"time"

	authorization "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization"
	"github.com/Azure/go-autorest/autorest/to"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	roleAssignmentCreateRetryCount = 7
	roleAssignmentCreateRetryDelay = 5 * time.Second
)

// CreateRoleAssignment creates a role assignment.
func (c *AzureClient) CreateRoleAssignment(ctx context.Context, scope, roleName, principalID string) (authorization.RoleAssignment, error) {
	roleDefinitionID, err := c.GetRoleDefinitionIDByName(ctx, "", roleName)
	if err != nil {
		return authorization.RoleAssignment{}, errors.Wrapf(err, "failed to get role definition id for role %s", roleName)
	}

	log.Debugf("Creating role assignment for principalID=%s with role=%s", principalID, roleName)
	parameters := authorization.RoleAssignmentCreateParameters{
		Properties: &authorization.RoleAssignmentProperties{
			RoleDefinitionID: roleDefinitionID.ID,
			PrincipalID:      to.StringPtr(principalID),
		},
	}

	// Adding retries to handle the propagation delay of the service principal.
	// Trying to create role assignment immediately after service principal is created
	// results in "PrincipalNotFound" error.
	for i := 0; i < roleAssignmentCreateRetryCount; i++ {
		result, err := c.roleAssignmentsClient.Create(ctx, scope, uuid.New().String(), parameters, nil)
		if err == nil {
			return result.RoleAssignment, nil
		}
		if IsAlreadyExists(err) {
			log.Warnf("Role assignment already exists for principalID=%s with role=%s", principalID, roleName)
			return result.RoleAssignment, err
		}
		time.Sleep(roleAssignmentCreateRetryDelay)
	}

	return authorization.RoleAssignment{}, err
}

// DeleteRoleAssignment deletes a role assignment.
func (c *AzureClient) DeleteRoleAssignment(ctx context.Context, roleAssignmentID string) (authorization.RoleAssignment, error) {
	log.Debugf("Deleting role assignment with id=%s", roleAssignmentID)
	o, err := c.roleAssignmentsClient.DeleteByID(ctx, roleAssignmentID, nil)
	return o.RoleAssignment, err
}
