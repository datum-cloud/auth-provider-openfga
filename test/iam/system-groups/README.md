# System Groups Policy Binding Test

This test verifies that system groups (like `system:authenticated-users`) work correctly in PolicyBinding resources.

## Test Overview

This test validates the system groups functionality by:

1. **Setup**: Creates necessary protected resources and roles
2. **PolicyBinding Creation**: Creates a PolicyBinding that binds `system:authenticated-users` to a role without requiring a UID
3. **Positive Test**: Verifies that users with `system:authenticated-users` group get access
4. **Negative Test**: Verifies that users without the system group are denied access
5. **Multiple Users Test**: Confirms the system group works for different authenticated users
6. **Multiple Permissions Test**: Tests both CREATE and GET permissions

## Key Features Tested

- **System Group Support**: PolicyBinding accepts system groups without UID validation
- **Authorization Webhook**: Webhooks correctly process group contextual tuples for system groups
- **Group Membership**: Users with `system:authenticated-users` in their groups get access
- **Access Control**: Users without the system group are properly denied access

## Test Structure

```
system-groups/
├── chainsaw-test.yaml              # Main test definition
├── protected-resources/
│   └── iam-user.yaml              # Protected resource for IAM Users
├── roles/
│   └── iam-user-creator.yaml      # Role with user creation permissions
└── README.md                      # This file
```

## Running the Test

To run this test using Chainsaw:

```bash
# From the auth-provider-openfga directory
chainsaw test test/iam/system-groups/
```

Or to run all IAM tests:

```bash
chainsaw test test/iam/
```

## Expected Behavior

The test should pass all steps, demonstrating that:

1. System groups can be used in PolicyBinding without UID
2. Users with `system:authenticated-users` group get appropriate access
3. Users without the system group are denied access
4. The implementation works consistently across multiple users and permissions

## Implementation Details

This test validates the changes made to support system groups:

- **PolicyBinding Controller**: Skips UID validation for system groups
- **OpenFGA Policy Reconciler**: Uses group names directly for system groups
- **Authorization Webhooks**: Adds group contextual tuples from user info
