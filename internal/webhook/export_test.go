package webhook

import (
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
)

// NewProtectedResourceCacheForTest creates a ProtectedResourceCache pre-populated
// with the provided items. This is only intended for use in tests.
func NewProtectedResourceCacheForTest(items []iamv1alpha1.ProtectedResource) *ProtectedResourceCache {
	return newProtectedResourceCacheFromItems(items)
}

// NewSystemGroupMaterializerForTest creates a SystemGroupMaterializer for use in
// tests. It is equivalent to NewSystemGroupMaterializer but is exported via the
// internal test helper file so it does not leak into production packages.
func NewSystemGroupMaterializerForTest(fgaClient openfgav1.OpenFGAServiceClient, storeID string) *SystemGroupMaterializer {
	return NewSystemGroupMaterializer(fgaClient, storeID)
}
