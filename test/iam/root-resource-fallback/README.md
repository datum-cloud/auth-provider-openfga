# Root Resource Fallback End-to-End Test

This test validates the root resource fallback functionality in the authorization webhook when no parent resource context is provided for collection operations.

## Test Overview

This test covers the scenario where:

1. **Collection Operation**: A collection operation (list, create, watch) is performed against a resource type
2. **No Parent Context**: The request does not include parent resource information in the user's extra data
3. **Root Resource Fallback**: The webhook should fallback to using the root resource (`iam.miloapis.com/Root:<api-group>/<kind>`) instead of failing
4. **ResourceKind Authorization**: Authorization is granted through ResourceKind PolicyBindings that bind to root resources

## Problem Being Solved

Before this fix, when a collection operation was performed without parent context, the webhook would:
- Try to build a parent resource from the request context
- Fail to find parent information
- Return an error and deny access

With the root resource fallback:
- Try to build a parent resource from the request context
- If no parent is found, fallback to using the root resource for the collection type
- Allow ResourceKind policies to grant access through root bindings

## Test Scenario

The test creates:

- A ResourceKind PolicyBinding that grants permissions to all resources of a specific kind
- A test user with the ResourceKind binding
- Tests collection operations (list) without parent context information
- Validates that the webhook uses root resource fallback and grants access
- Tests that unauthorized users are still correctly denied access

## Key Validation Points

1. **Collection Without Parent**: List operation without parent context should succeed (not fail with error)
2. **Root Resource Authorization**: Access is granted through root resource binding mechanism
3. **ResourceKind Binding**: The ResourceKind PolicyBinding works correctly with root resource fallback
4. **Access Control**: Users without ResourceKind bindings are still correctly denied access
5. **Webhook Robustness**: The webhook handles missing parent context gracefully instead of failing

## Test Files

- `chainsaw-test.yaml`: Main test orchestration
- `roles/root-fallback-admin.yaml`: Role definition with resource permissions
- `user.yaml`: Test user who receives the ResourceKind binding
- `unauthorized-user.yaml`: User without any bindings (for negative testing)

## Running the Test

```bash
chainsaw test --test-dir auth-provider-openfga/test/iam/root-resource-fallback/
```

This test validates that the authorization webhook gracefully handles collection operations without parent context by falling back to root resource authorization.
