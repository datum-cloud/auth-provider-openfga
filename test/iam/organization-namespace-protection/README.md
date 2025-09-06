# Organization Namespace Protection Test

This test validates that the OpenFGA auth provider correctly enforces
organization-level namespace boundaries during authorization checks.

## Test Scenarios

### 1. Allowed Access - Correct Namespace
- **User**: `acme-admin` with Organization parent context (`acme`)
- **Request**: List groups in `organization-acme` namespace
- **Expected**: Access allowed (namespace matches organization)

### 2. Denied Access - Wrong Namespace
- **User**: `acme-admin` with Organization parent context (`acme`)
- **Request**: List groups in `organization-contoso` namespace
- **Expected**: Access denied with namespace mismatch evaluation error

### 3. Non-Organization Request - No Validation
- **User**: `regular-user` with no parent context
- **Request**: List groups in `organization-contoso` namespace
- **Expected**: Regular authorization flow (no namespace validation)

## Key Features Tested

1. **Namespace Validation**: Organization-scoped requests must use the correct
   namespace pattern
2. **Error Format**: Namespace mismatches return proper evaluation errors
3. **Scope Detection**: Only organization-scoped requests undergo namespace
   validation
4. **Backward Compatibility**: Non-organization requests are unaffected

## Resources Created

- **Organizations**: `acme`, `contoso`
- **Namespaces**: `organization-acme`, `organization-contoso`
- **Users**: `acme-admin`, `regular-user`
- **Role**: `group-admin` with IAM group permissions
- **PolicyBinding**: Grants `acme-admin` access to `acme` organization

## Test Flow

1. Deploy protected resources and wait for readiness
2. Create organizations and namespaces
3. Create users, roles, and policy bindings
4. Test allowed access with correct namespace
5. Test denied access with wrong namespace
6. Test non-organization request (no validation)
7. Cleanup test resources

## Expected Outcomes

- ✅ Organization admins can access resources in their organization's namespace
- ✅ Organization admins cannot access resources in other organization namespaces
- ✅ Non-organization requests bypass namespace validation
- ✅ Proper webhook error responses for validation failures
