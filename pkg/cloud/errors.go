package cloud

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/go-autorest/autorest"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/pkg/errors"
)

const (
	// GraphErrorCodeResourceNotFound is the error code for resource not found.
	GraphErrorCodeResourceNotFound = "Request_ResourceNotFound"
	// GraphErrorCodeMultipleObjectsWithSameKeyValue is the error code for multiple objects with same key value.
	GraphErrorCodeMultipleObjectsWithSameKeyValue = "Request_MultipleObjectsWithSameKeyValue"
)

// GraphError is a custom error type for Graph API errors.
type GraphError struct {
	errorable *odataerrors.ODataError
}

// IsNotFound returns true if the given error is a NotFound error.
func IsNotFound(err error) bool {
	return strings.Contains(err.Error(), "not found")
}

// IsRoleAssignmentAlreadyDeleted returns true if the given error is a role assignment already deleted error.
// Ref: https://docs.microsoft.com/en-us/rest/api/authorization/role-assignments/delete#response
func IsRoleAssignmentAlreadyDeleted(err error) bool {
	derr := autorest.DetailedError{}
	return errors.As(err, &derr) && derr.StatusCode == http.StatusNoContent
}

// IsAlreadyExists parses the error message to check if it's resource already exists error.
func IsAlreadyExists(err error) bool {
	derr := autorest.DetailedError{}
	return errors.As(err, &derr) && derr.StatusCode == http.StatusConflict
}

// IsFederatedCredentialNotFound returns true if the given error is a federated credential not found error.
func IsFederatedCredentialNotFound(err error) bool {
	gerr := GraphError{}
	return errors.As(err, &gerr) && *gerr.PublicError.GetCode() == GraphErrorCodeResourceNotFound
}

// IsFederatedCredentialAlreadyExists returns true if the given error is a federated credential already exists error.
// E1202 22:40:05.500821  867104 main.go:57] "failed to add federated identity credential" err="code: Request_MultipleObjectsWithSameKeyValue, message: FederatedIdentityCredential with name aramase-default-cred already exists."
func IsFederatedCredentialAlreadyExists(err error) bool {
	switch v := err.(type) {
	case *odataerrors.ODataError:
		errorable := v.GetError()

		fmt.Printf("error: %s | %s\n",
			*errorable.GetCode(),
			*errorable.GetMessage(),
		)
		details := errorable.GetDetails()
		for idx, v := range details {
			fmt.Printf("  %d - %s %s\n",
				idx,
				*v.GetMessage(),
				*v.GetCode(),
			)
		}
		extras := v.GetAdditionalData()
		for k, v := range extras {
			fmt.Printf("k: %s: %T %+v\n", k, v, v)
		}
		return *errorable.GetCode() == GraphErrorCodeMultipleObjectsWithSameKeyValue

	default:
		return false
	}
}

// Error returns the error message.
func (e GraphError) Error() string {
	if e. == nil {
		return ""
	}
	return fmt.Sprintf("code: %s, message: %s", *e.PublicError.GetCode(), *e.PublicError.GetMessage())
}
