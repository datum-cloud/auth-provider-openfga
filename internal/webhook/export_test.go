package webhook

import (
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

// NewProtectedResourceCacheForTest creates a ProtectedResourceCache pre-populated
// with the provided items. This is only intended for use in tests.
func NewProtectedResourceCacheForTest(items []iamv1alpha1.ProtectedResource) *ProtectedResourceCache {
	return newProtectedResourceCacheFromItems(items)
}

// NewProjectOrganizationCacheForTest creates a ProjectOrganizationCache
// pre-populated with the provided items. This is only intended for use in tests.
func NewProjectOrganizationCacheForTest(items []resourcemanagerv1alpha1.Project) *ProjectOrganizationCache {
	return newProjectOrganizationCacheFromItems(items)
}
