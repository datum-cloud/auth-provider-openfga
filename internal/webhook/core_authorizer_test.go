package webhook_test

import (
	"context"
	"errors"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// mockAttributes is a simple mock for authorizer.Attributes
type mockAttributes struct {
	authorizer.Attributes
	user     user.Info
	verb     string
	apiGroup string
	resource string
	name     string
}

func (m *mockAttributes) GetUser() user.Info      { return m.user }
func (m *mockAttributes) GetVerb() string         { return m.verb }
func (m *mockAttributes) GetAPIGroup() string     { return m.apiGroup }
func (m *mockAttributes) GetResource() string     { return m.resource }
func (m *mockAttributes) GetName() string         { return m.name }
func (m *mockAttributes) IsResourceRequest() bool { return true }

// mockFGAClient is a mock of OpenFGAServiceClient for testing.
type mockFGAClient struct {
	openfgav1.OpenFGAServiceClient
	CheckFunc func(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error)
}

func (m *mockFGAClient) Check(ctx context.Context, in *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
	if m.CheckFunc != nil {
		return m.CheckFunc(ctx, in)
	}
	return nil, errors.New("CheckFunc not implemented")
}

// mockK8sClient is a mock of client.Client for testing.
type mockK8sClient struct {
	client.Client
	listFunc func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error
}

func (m *mockK8sClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if m.listFunc != nil {
		return m.listFunc(ctx, list, opts...)
	}
	return errors.New("List not implemented")
}

func TestCoreControlPlaneAuthorizer_Authorize_Integration(t *testing.T) {
	testCases := []struct {
		name               string
		attributes         authorizer.Attributes
		k8sListFunc        func(client.ObjectList)
		fgaCheckFunc       func(*testing.T, *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error)
		expectedDecision   authorizer.Decision
		expectedErrorMsg   string
		expectFgaCheckCall bool
	}{
		{
			name: "allowed resource get with registered parent",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				name:     "wkld-123",
				verb:     "get",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
						iamv1alpha1.ParentKindExtraKey:     {"Project"},
						iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
					},
				},
			},
			k8sListFunc: func(list client.ObjectList) {
				l := list.(*iamv1alpha1.ProtectedResourceList)
				l.Items = []iamv1alpha1.ProtectedResource{
					{
						Spec: iamv1alpha1.ProtectedResourceSpec{
							ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
							Plural:      "workloads",
							Kind:        "Workload",
							Permissions: []string{"get"},
							ParentResources: []iamv1alpha1.ParentResourceRef{
								{APIGroup: "resourcemanager.miloapis.com", Kind: "Project"},
							},
						},
					},
				}
			},
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				assert.Equal(t, "compute.miloapis.com/Workload:wkld-123", req.TupleKey.Object)
				require.NotNil(t, req.ContextualTuples)
				require.Len(t, req.ContextualTuples.TupleKeys, 1)
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", req.ContextualTuples.TupleKeys[0].User)
				assert.Equal(t, "parent", req.ContextualTuples.TupleKeys[0].Relation)
				assert.Equal(t, "compute.miloapis.com/Workload:wkld-123", req.ContextualTuples.TupleKeys[0].Object)
				return &openfgav1.CheckResponse{Allowed: true}, nil
			},
			expectedDecision:   authorizer.DecisionAllow,
			expectFgaCheckCall: true,
		},
		{
			name: "denied collection create with parent context",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				verb:     "create",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"resourcemanager.miloapis.com"},
						iamv1alpha1.ParentKindExtraKey:     {"Project"},
						iamv1alpha1.ParentNameExtraKey:     {"proj-xyz"},
					},
				},
			},
			k8sListFunc: func(list client.ObjectList) {
				l := list.(*iamv1alpha1.ProtectedResourceList)
				l.Items = []iamv1alpha1.ProtectedResource{
					{
						Spec: iamv1alpha1.ProtectedResourceSpec{
							ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
							Plural:      "workloads",
							Kind:        "Workload",
							Permissions: []string{"create"},
						},
					},
				}
			},
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				assert.Equal(t, "resourcemanager.miloapis.com/Project:proj-xyz", req.TupleKey.Object)
				assert.Nil(t, req.ContextualTuples)
				return &openfgav1.CheckResponse{Allowed: false}, nil
			},
			expectedDecision:   authorizer.DecisionDeny,
			expectFgaCheckCall: true,
		},
		{
			name: "permission not registered",
			attributes: &mockAttributes{
				apiGroup: "foo.com",
				resource: "bars",
				verb:     "get",
				user:     &user.DefaultInfo{UID: "user-abc"},
			},
			k8sListFunc: func(list client.ObjectList) {
				l := list.(*iamv1alpha1.ProtectedResourceList)
				l.Items = []iamv1alpha1.ProtectedResource{}
			},
			expectedDecision:   authorizer.DecisionDeny,
			expectedErrorMsg:   "permission 'foo.com/bars.get' not registered",
			expectFgaCheckCall: false,
		},
		{
			name: "no contextual tuple for unregistered parent",
			attributes: &mockAttributes{
				apiGroup: "compute.miloapis.com",
				resource: "workloads",
				name:     "wkld-123",
				verb:     "get",
				user: &user.DefaultInfo{
					Name: "test-user",
					UID:  "user-abc",
					Extra: map[string][]string{
						iamv1alpha1.ParentAPIGroupExtraKey: {"some.other.api"},
						iamv1alpha1.ParentKindExtraKey:     {"OtherKind"},
						iamv1alpha1.ParentNameExtraKey:     {"other-123"},
					},
				},
			},
			k8sListFunc: func(list client.ObjectList) {
				l := list.(*iamv1alpha1.ProtectedResourceList)
				l.Items = []iamv1alpha1.ProtectedResource{
					{
						Spec: iamv1alpha1.ProtectedResourceSpec{
							ServiceRef:  iamv1alpha1.ServiceReference{Name: "compute.miloapis.com"},
							Plural:      "workloads",
							Kind:        "Workload",
							Permissions: []string{"get"},
							ParentResources: []iamv1alpha1.ParentResourceRef{
								{APIGroup: "resourcemanager.miloapis.com", Kind: "Project"},
							},
						},
					},
				}
			},
			fgaCheckFunc: func(t *testing.T, req *openfgav1.CheckRequest) (*openfgav1.CheckResponse, error) {
				assert.Equal(t, "compute.miloapis.com/Workload:wkld-123", req.TupleKey.Object)
				assert.Nil(t, req.ContextualTuples)
				return &openfgav1.CheckResponse{Allowed: true}, nil
			},
			expectedDecision:   authorizer.DecisionAllow,
			expectFgaCheckCall: true,
		},
		{
			name: "deny if user has no UID",
			attributes: &mockAttributes{
				user: &user.DefaultInfo{Name: "no-uid-user"},
			},
			k8sListFunc: func(list client.ObjectList) {
				l := list.(*iamv1alpha1.ProtectedResourceList)
				l.Items = []iamv1alpha1.ProtectedResource{
					{
						Spec: iamv1alpha1.ProtectedResourceSpec{
							Permissions: []string{"get"},
						},
					},
				}
			},
			expectedDecision:   authorizer.DecisionDeny,
			expectedErrorMsg:   "user UID is required",
			expectFgaCheckCall: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fgaCheckCalled := false
			mockFGA := &mockFGAClient{
				CheckFunc: func(ctx context.Context, req *openfgav1.CheckRequest, opts ...grpc.CallOption) (*openfgav1.CheckResponse, error) {
					fgaCheckCalled = true
					if tc.fgaCheckFunc != nil {
						return tc.fgaCheckFunc(t, req)
					}
					return nil, errors.New("FGA CheckFunc not provided")
				},
			}
			mockK8s := &mockK8sClient{
				listFunc: func(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
					if tc.k8sListFunc != nil {
						tc.k8sListFunc(list)
					}
					return nil
				},
			}

			auth := &webhook.CoreControlPlaneAuthorizer{
				FGAClient:  mockFGA,
				K8sClient:  mockK8s,
				FGAStoreID: "test_store",
			}

			decision, _, err := auth.Authorize(context.Background(), tc.attributes)

			assert.Equal(t, tc.expectedDecision, decision)
			if tc.expectedErrorMsg != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedErrorMsg)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.expectFgaCheckCall, fgaCheckCalled)
		})
	}
}
