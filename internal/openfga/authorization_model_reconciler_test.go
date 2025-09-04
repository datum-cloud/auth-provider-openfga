package openfga

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// MockOpenFGAServiceClient is a mock implementation of openfgav1.OpenFGAServiceClient for testing
type MockOpenFGAServiceClient struct {
	openfgav1.OpenFGAServiceClient
	ReadAuthorizationModelsFunc func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error)
	ReadAuthorizationModelFunc  func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error)
	WriteAuthorizationModelFunc func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error)
}

func (m *MockOpenFGAServiceClient) ReadAuthorizationModels(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
	if m.ReadAuthorizationModelsFunc != nil {
		return m.ReadAuthorizationModelsFunc(ctx, in, opts...)
	}
	return &openfgav1.ReadAuthorizationModelsResponse{}, nil
}

func (m *MockOpenFGAServiceClient) ReadAuthorizationModel(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
	if m.ReadAuthorizationModelFunc != nil {
		return m.ReadAuthorizationModelFunc(ctx, in, opts...)
	}
	return &openfgav1.ReadAuthorizationModelResponse{}, nil
}

func (m *MockOpenFGAServiceClient) WriteAuthorizationModel(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
	if m.WriteAuthorizationModelFunc != nil {
		return m.WriteAuthorizationModelFunc(ctx, in, opts...)
	}
	return &openfgav1.WriteAuthorizationModelResponse{}, nil
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel(t *testing.T) {
	// Set up test logger
	logf.SetLogger(zap.New())

	testCases := []struct {
		name                            string
		protectedResources              []iamdatumapiscomv1alpha1.ProtectedResource
		currentModel                    *openfgav1.AuthorizationModel
		expectedWriteAuthorizationCalls int
		expectedError                   string
	}{
		{
			name: "should skip write when models are identical",
			protectedResources: []iamdatumapiscomv1alpha1.ProtectedResource{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-resource"},
					Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "test.service.com"},
						Plural:      "testresources",
						Kind:        "TestResource",
						Permissions: []string{"get", "list"},
					},
				},
			},
			currentModel: &openfgav1.AuthorizationModel{
				SchemaVersion: "1.2",
				TypeDefinitions: []*openfgav1.TypeDefinition{
					// Create the exact same type definitions that would be generated
					getUserTypeDefinition(),
					getUserGroupTypeDefinition(),
					getRoleTypeDefinition([]string{"test.service.com/testresources.get", "test.service.com/testresources.list"}),
					getRoleBindingTypeDefinition([]string{"test.service.com/testresources.get", "test.service.com/testresources.list"}),
					getRootTypeDefinition([]string{"test.service.com/testresources.get", "test.service.com/testresources.list"}, []string{"test.service.com/TestResource"}),
					// Add the resource type definition that would be generated
					{
						Type: "test.service.com/TestResource",
						Metadata: &openfgav1.Metadata{
							Relations: map[string]*openfgav1.RelationMetadata{
								"iam.miloapis.com/RoleBinding": {
									DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
										{Type: "iam.miloapis.com/RoleBinding"},
									},
								},
								"iam.miloapis.com/RootBinding": {
									DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
										{Type: "iam.miloapis.com/Root"},
									},
								},
							},
							SourceInfo: &openfgav1.SourceInfo{
								File: "dynamically_managed_iam_datumapis_com.fga",
							},
							Module: "test.service.com",
						},
						Relations: map[string]*openfgav1.Userset{
							"iam.miloapis.com/RoleBinding": {
								Userset: &openfgav1.Userset_This{},
							},
							"iam.miloapis.com/RootBinding": {
								Userset: &openfgav1.Userset_This{},
							},
							hashPermission("test.service.com/testresources.get"): {
								Userset: &openfgav1.Userset_Union{
									Union: &openfgav1.Usersets{
										Child: []*openfgav1.Userset{
											{
												Userset: &openfgav1.Userset_TupleToUserset{
													TupleToUserset: &openfgav1.TupleToUserset{
														Tupleset: &openfgav1.ObjectRelation{
															Relation: "iam.miloapis.com/RoleBinding",
														},
														ComputedUserset: &openfgav1.ObjectRelation{
															Relation: hashPermission("test.service.com/testresources.get"),
														},
													},
												},
											},
											{
												Userset: &openfgav1.Userset_TupleToUserset{
													TupleToUserset: &openfgav1.TupleToUserset{
														Tupleset: &openfgav1.ObjectRelation{
															Relation: "iam.miloapis.com/RootBinding",
														},
														ComputedUserset: &openfgav1.ObjectRelation{
															Relation: hashPermission("test.service.com/testresources.get"),
														},
													},
												},
											},
										},
									},
								},
							},
							hashPermission("test.service.com/testresources.list"): {
								Userset: &openfgav1.Userset_Union{
									Union: &openfgav1.Usersets{
										Child: []*openfgav1.Userset{
											{
												Userset: &openfgav1.Userset_TupleToUserset{
													TupleToUserset: &openfgav1.TupleToUserset{
														Tupleset: &openfgav1.ObjectRelation{
															Relation: "iam.miloapis.com/RoleBinding",
														},
														ComputedUserset: &openfgav1.ObjectRelation{
															Relation: hashPermission("test.service.com/testresources.list"),
														},
													},
												},
											},
											{
												Userset: &openfgav1.Userset_TupleToUserset{
													TupleToUserset: &openfgav1.TupleToUserset{
														Tupleset: &openfgav1.ObjectRelation{
															Relation: "iam.miloapis.com/RootBinding",
														},
														ComputedUserset: &openfgav1.ObjectRelation{
															Relation: hashPermission("test.service.com/testresources.list"),
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedWriteAuthorizationCalls: 0, // Should not call WriteAuthorizationModel
		},
		{
			name: "should write when models are different",
			protectedResources: []iamdatumapiscomv1alpha1.ProtectedResource{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "test-resource"},
					Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
						ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "test.service.com"},
						Plural:      "testresources",
						Kind:        "TestResource",
						Permissions: []string{"get", "list"},
					},
				},
			},
			currentModel: &openfgav1.AuthorizationModel{
				SchemaVersion: "1.2",
				TypeDefinitions: []*openfgav1.TypeDefinition{
					// Different model - missing some expected type definitions
					getUserTypeDefinition(),
					getUserGroupTypeDefinition(),
				},
			},
			expectedWriteAuthorizationCalls: 1, // Should call WriteAuthorizationModel once
		},
		{
			name:                            "should write when no current model exists",
			protectedResources:              []iamdatumapiscomv1alpha1.ProtectedResource{},
			currentModel:                    &openfgav1.AuthorizationModel{}, // Empty model
			expectedWriteAuthorizationCalls: 1,                               // Should call WriteAuthorizationModel once
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			writeAuthorizationCalls := 0

			mockClient := &MockOpenFGAServiceClient{
				ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
					// Return that we have an authorization model
					return &openfgav1.ReadAuthorizationModelsResponse{
						AuthorizationModels: []*openfgav1.AuthorizationModel{
							{Id: "test-model-id"},
						},
					}, nil
				},
				ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
					// Return the current model provided in test case
					return &openfgav1.ReadAuthorizationModelResponse{
						AuthorizationModel: tc.currentModel,
					}, nil
				},
				WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
					writeAuthorizationCalls++
					return &openfgav1.WriteAuthorizationModelResponse{
						AuthorizationModelId: "new-model-id",
					}, nil
				},
			}

			reconciler := &AuthorizationModelReconciler{
				StoreID: "test-store",
				OpenFGA: mockClient,
			}

			ctx := logf.IntoContext(context.Background(), logf.Log)
			err := reconciler.ReconcileAuthorizationModel(ctx, tc.protectedResources)

			if tc.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.expectedWriteAuthorizationCalls, writeAuthorizationCalls,
				"Expected %d WriteAuthorizationModel calls, but got %d",
				tc.expectedWriteAuthorizationCalls, writeAuthorizationCalls)
		})
	}
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel_NoCurrentModel(t *testing.T) {
	// Test case where no authorization model exists yet
	logf.SetLogger(zap.New())

	writeAuthorizationCalls := 0

	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			// Return empty list - no models exist yet
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{},
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeAuthorizationCalls++
			// Verify the request contains expected data
			assert.Equal(t, "test-store", in.StoreId)
			assert.Equal(t, "1.2", in.SchemaVersion)
			assert.Len(t, in.TypeDefinitions, 4) // Minimal model has 4 type definitions
			return &openfgav1.WriteAuthorizationModelResponse{
				AuthorizationModelId: "new-model-id",
			}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	ctx := logf.IntoContext(context.Background(), logf.Log)
	err := reconciler.ReconcileAuthorizationModel(ctx, []iamdatumapiscomv1alpha1.ProtectedResource{})

	require.NoError(t, err)
	assert.Equal(t, 1, writeAuthorizationCalls, "Should call WriteAuthorizationModel once when no current model exists")
}

func TestAuthorizationModelReconciler_ReconcileAuthorizationModel_WithConditions(t *testing.T) {
	// Test that existing conditions are preserved in the merged model
	logf.SetLogger(zap.New())

	writeAuthorizationCalls := 0
	existingConditions := map[string]*openfgav1.Condition{
		"test_condition": {
			Name:       "test_condition",
			Expression: "param.test == 'value'",
		},
	}

	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{
					{Id: "test-model-id"},
				},
			}, nil
		},
		ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
			return &openfgav1.ReadAuthorizationModelResponse{
				AuthorizationModel: &openfgav1.AuthorizationModel{
					SchemaVersion:   "1.2",
					Conditions:      existingConditions,
					TypeDefinitions: []*openfgav1.TypeDefinition{}, // Different model
				},
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeAuthorizationCalls++
			// Verify that conditions are preserved
			assert.Equal(t, existingConditions, in.Conditions)
			return &openfgav1.WriteAuthorizationModelResponse{
				AuthorizationModelId: "new-model-id",
			}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	ctx := logf.IntoContext(context.Background(), logf.Log)
	err := reconciler.ReconcileAuthorizationModel(ctx, []iamdatumapiscomv1alpha1.ProtectedResource{})

	require.NoError(t, err)
	assert.Equal(t, 1, writeAuthorizationCalls, "Should call WriteAuthorizationModel once")
}

// TestAuthorizationModelReconciler_OrderingOptimization tests that models with different
// ordering but same content are correctly identified as identical
func TestAuthorizationModelReconciler_OrderingOptimization(t *testing.T) {
	// Setup logging
	logf.SetLogger(zap.New())
	ctx := logf.IntoContext(context.TODO(), logf.Log)

	// Create realistic protected resources that would generate the same model
	protectedResources := []iamdatumapiscomv1alpha1.ProtectedResource{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "network-pr"},
			Spec: iamdatumapiscomv1alpha1.ProtectedResourceSpec{
				ServiceRef:  iamdatumapiscomv1alpha1.ServiceReference{Name: "networking.miloapis.com"},
				Kind:        "Network",
				Plural:      "networks",
				Permissions: []string{"read", "write"},
			},
		},
	}

	// Create a reconciler to generate the expected model
	tempReconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: nil, // We won't call OpenFGA methods
	}

	// Generate the expected model that would be created
	expectedModel, err := tempReconciler.createExpectedAuthorizationModel(protectedResources)
	require.NoError(t, err)

	// Create the same model but simulate different ordering from OpenFGA
	// by manually reordering the TypeDefinitions
	currentModelFromOpenFGA := proto.Clone(expectedModel).(*openfgav1.AuthorizationModel)
	if len(currentModelFromOpenFGA.TypeDefinitions) > 1 {
		// Reverse the order to simulate different ordering
		typeDefs := currentModelFromOpenFGA.TypeDefinitions
		for i, j := 0, len(typeDefs)-1; i < j; i, j = i+1, j-1 {
			typeDefs[i], typeDefs[j] = typeDefs[j], typeDefs[i]
		}
	}

	// Verify that proto.Equal returns false (confirming the ordering issue)
	assert.False(t, proto.Equal(currentModelFromOpenFGA, expectedModel),
		"proto.Equal should return false for models with different ordering")

	// Verify that our go-cmp based comparison returns true despite ordering differences
	assert.True(t, authorizationModelsEqual(currentModelFromOpenFGA, expectedModel),
		"authorizationModelsEqual should return true for models with different ordering")

	writeCallCount := 0
	mockClient := &MockOpenFGAServiceClient{
		ReadAuthorizationModelsFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelsRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelsResponse, error) {
			return &openfgav1.ReadAuthorizationModelsResponse{
				AuthorizationModels: []*openfgav1.AuthorizationModel{
					{Id: "model1"},
				},
			}, nil
		},
		ReadAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.ReadAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.ReadAuthorizationModelResponse, error) {
			return &openfgav1.ReadAuthorizationModelResponse{
				AuthorizationModel: currentModelFromOpenFGA, // Return model with different ordering
			}, nil
		},
		WriteAuthorizationModelFunc: func(ctx context.Context, in *openfgav1.WriteAuthorizationModelRequest, opts ...grpc.CallOption) (*openfgav1.WriteAuthorizationModelResponse, error) {
			writeCallCount++
			return &openfgav1.WriteAuthorizationModelResponse{}, nil
		},
	}

	reconciler := &AuthorizationModelReconciler{
		StoreID: "test-store",
		OpenFGA: mockClient,
	}

	// This should NOT call WriteAuthorizationModel since models are semantically equal
	err = reconciler.ReconcileAuthorizationModel(ctx, protectedResources)
	require.NoError(t, err)

	// Verify that WriteAuthorizationModel was not called
	assert.Equal(t, 0, writeCallCount, "WriteAuthorizationModel should not be called when models are semantically equal")
}

// TestAuthorizationModelsEqual_TypeDefinitionOrdering tests that models with different
// TypeDefinition ordering but same content are correctly identified as identical
func TestAuthorizationModelsEqual_TypeDefinitionOrdering(t *testing.T) {
	// Create two identical models but with different TypeDefinition ordering
	model1 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "iam.miloapis.com/InternalUser"},
			{Type: "networking.miloapis.com/Network"},
			{Type: "iam.miloapis.com/InternalRole"},
		},
	}

	model2 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{Type: "iam.miloapis.com/InternalRole"},
			{Type: "iam.miloapis.com/InternalUser"},
			{Type: "networking.miloapis.com/Network"},
		},
	}

	// Test that our go-cmp based comparison handles ordering correctly
	assert.True(t, authorizationModelsEqual(model1, model2),
		"authorizationModelsEqual should return true for models with different TypeDefinition ordering")

	// Verify that the direct go-cmp comparison would detect differences without our sorting options
	assert.False(t, cmp.Equal(model1, model2, protocmp.Transform()), "Raw cmp.Equal should detect ordering differences")

	// Test that different schema versions are detected as different
	model3 := &openfgav1.AuthorizationModel{
		SchemaVersion:   "1.1", // Different version
		TypeDefinitions: model2.TypeDefinitions,
	}
	assert.False(t, authorizationModelsEqual(model1, model3),
		"Models with different schema versions should not be equal")
}

func TestAuthorizationModelReconciler_MapOrderingOptimization(t *testing.T) {
	// Create two identical models but with different map ordering
	model1 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "test.service.com/TestResource",
				Relations: map[string]*openfgav1.Userset{
					// Order: A, B, C
					"iam.miloapis.com/RoleBinding":                       {Userset: &openfgav1.Userset_This{}},
					"iam.miloapis.com/RootBinding":                       {Userset: &openfgav1.Userset_This{}},
					hashPermission("test.service.com/testresources.get"): {Userset: &openfgav1.Userset_This{}},
				},
				Metadata: &openfgav1.Metadata{
					Relations: map[string]*openfgav1.RelationMetadata{
						// Order: A, B, C
						"iam.miloapis.com/RoleBinding": {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: "iam.miloapis.com/RoleBinding"},
							},
						},
						"iam.miloapis.com/RootBinding": {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: "iam.miloapis.com/Root"},
							},
						},
					},
				},
			},
		},
	}

	model2 := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "test.service.com/TestResource",
				Relations: map[string]*openfgav1.Userset{
					// Order: C, B, A (reversed)
					hashPermission("test.service.com/testresources.get"): {Userset: &openfgav1.Userset_This{}},
					"iam.miloapis.com/RootBinding":                       {Userset: &openfgav1.Userset_This{}},
					"iam.miloapis.com/RoleBinding":                       {Userset: &openfgav1.Userset_This{}},
				},
				Metadata: &openfgav1.Metadata{
					Relations: map[string]*openfgav1.RelationMetadata{
						// Order: B, A (reversed)
						"iam.miloapis.com/RootBinding": {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: "iam.miloapis.com/Root"},
							},
						},
						"iam.miloapis.com/RoleBinding": {
							DirectlyRelatedUserTypes: []*openfgav1.RelationReference{
								{Type: "iam.miloapis.com/RoleBinding"},
							},
						},
					},
				},
			},
		},
	}

	// Note: proto.Equal might not always detect differences due to map ordering
	// The important thing is that our enhanced authorizationModelsEqual handles it correctly

	// Verify that our enhanced authorizationModelsEqual handles map ordering correctly
	assert.True(t, authorizationModelsEqual(model1, model2), "authorizationModelsEqual should handle map ordering differences")
}

func TestAuthorizationModelsEqual_IdFieldIgnored(t *testing.T) {
	// Create two identical models, but one has an id field
	modelWithId := &openfgav1.AuthorizationModel{
		Id:            "01JZ3JDMRJ99MFDMCX65ZNHBHG",
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "iam.miloapis.com/InternalUser",
				Metadata: &openfgav1.Metadata{
					Module: iamdatumapiscomv1alpha1.SchemeGroupVersion.Group,
				},
			},
		},
	}

	modelWithoutId := &openfgav1.AuthorizationModel{
		SchemaVersion: "1.2",
		TypeDefinitions: []*openfgav1.TypeDefinition{
			{
				Type: "iam.miloapis.com/InternalUser",
				Metadata: &openfgav1.Metadata{
					Module: iamdatumapiscomv1alpha1.SchemeGroupVersion.Group,
				},
			},
		},
	}

	// They should be considered equal despite the id difference
	assert.True(t, authorizationModelsEqual(modelWithId, modelWithoutId))
	assert.True(t, authorizationModelsEqual(modelWithoutId, modelWithId))
}
