# ResourceKind Policy Bindings End-to-End Test

This test validates the new ResourceKind functionality in PolicyBindings, which allows system-wide access to all resources of a specific kind.

## Test Overview

The test covers the complete flow:

1. **PolicyBinding Controller**: Creates a PolicyBinding with `resourceSelector.resourceKind` instead of `resourceSelector.resourceRef`
2. **OpenFGA Tuples**: Verifies that the controller creates the correct tuples binding to root objects (`iam.miloapis.com/Root:<api-group>/<kind>`)
3. **Authorization Webhook**: Tests that the webhook adds context tuples linking specific resources to their root types
4. **Authorization Decision**: Validates that users with ResourceKind bindings can access any resource of that kind

## Test Scenario

The test creates:

- A `ResourceKind` PolicyBinding that grants `resourcekind.miloapis.com-organizationowner` role to a user for **all Organizations**
- Two separate Organization resources (`test-org-1` and `test-org-2`)
- Tests that the user can access **both** organizations (proving system-wide access)
- Tests that an unauthorized user **cannot** access any organizations

## Key Validation Points

1. **ResourceKind Binding Creation**: PolicyBinding with `resourceSelector.resourceKind` is created and reaches Ready state
2. **System-Wide Access**: User can access multiple different organization instances with a single ResourceKind binding
3. **Authorization Inheritance**: Access is granted through the root binding mechanism, not specific resource bindings
4. **Access Control**: Users without the ResourceKind binding are correctly denied access

## Test Files

- `chainsaw-test.yaml`: Main test orchestration
- `roles/resourcekind-organizationowner.yaml`: Role definition with organization permissions
- `user.yaml`: Test user who receives the ResourceKind binding
- `unauthorized-user.yaml`: User without any bindings (for negative testing)
- `organization1.yaml` & `organization2.yaml`: Test organization resources

## Running the Test

```bash
chainsaw test --test-dir auth-provider-openfga/test/iam/resourcekind-policy-bindings/
```

This test validates that the ResourceKind functionality works end-to-end from PolicyBinding creation through authorization decisions.
