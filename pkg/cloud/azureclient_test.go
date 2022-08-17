package cloud

import "testing"

func TestGetTenantID(t *testing.T) {
	rmEndpoint := "https://management.azure.com/"
	subscriptionID := "c80801f3-5848-4f8f-9c7a-dc0052a3655d"
	tenantID, err := GetTenantID(rmEndpoint, subscriptionID)
	if err != nil {
		t.Fatalf("GetTenantID failed: %v", err)
	}
	t.Logf("tenantID: %s", tenantID)
}
