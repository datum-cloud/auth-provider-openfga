# OpenFGA Integration

This document describes the detailed implementation of how the auth provider
integrates with OpenFGA to provide relationship-based authorization for Milo
resources.

The integration is heavily inspired by the [OpenFGA custom roles modeling
guide][custom-roles]. For background on OpenFGA concepts, refer to the [OpenFGA
core documentation][openfga-docs].

[custom-roles]: https://openfga.dev/docs/modeling/custom-roles
[openfga-docs]: https://openfga.dev/docs

## Authorization Model

The auth provider dynamically manages the [OpenFGA Authorization
Model][authorization-model] based on the resources registered through
[Kubernetes Custom Resource Definitions (CRDs)][k8s-crds]. This creates a
flexible authorization system that adapts as new resource types are added to the
Milo platform.

[authorization-model]:
    https://openfga.dev/docs/concepts#what-is-an-authorization-model
[k8s-crds]:
    https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/

### Dynamic Type Creation

A new OpenFGA Type Definition is created for every resource defined in a
`ProtectedResource` using the fully qualified resource name format:

**Format**: `{APIGroup}/{Kind}` **Example**:
`resourcemanager.miloapis.com/Organization`

> [!NOTE]
>
> While the [OpenFGA schema language][openfga-schema] does not support `/` or
> `.` characters in type definitions, OpenFGA supports using these characters
> when creating types through the [OpenFGA API][openfga-api], which is how this
> system operates.

[openfga-schema]: https://openfga.dev/docs/configuration-language
[openfga-api]: https://openfga.dev/api/service

### Model Integration

The system integrates with existing OpenFGA models by:
1. Reading the current authorization model using the [OpenFGA Read Authorization
   Model API][read-model-api]
2. Generating new [type definitions][type-definitions] for registered resources
3. Merging the generated model with the existing model
4. Overwriting any existing type definitions that match the managed naming
   pattern

[read-model-api]:
    https://openfga.dev/api/service#/Authorization%20Models/ReadAuthorizationModel
[type-definitions]: https://openfga.dev/docs/concepts#what-is-a-type-definition

### Permission Relations

Each resource type gets permission relations created for:
- **Direct permissions**: Permissions defined in the resource's
  `ProtectedResource.spec.permissions`
- **Child permissions**: Permissions from resources that have this resource as a
  parent
- **Inherited permissions**: Permissions that can be granted through parent
  relationships

### Core IAM Types

The system defines several core IAM types that form the foundation of all
authorization models. Understanding these types helps you interpret OpenFGA
queries and tuples:

- **`iam.miloapis.com/InternalUser`** - Represents authenticated users in the
  system. Every authorization query uses this type to identify who is making the
  request. You'll see this in the `user` field of OpenFGA tuples.

- **`iam.miloapis.com/InternalUserGroup`** - Represents groups that users belong
  to (like `system:authenticated` or custom business groups). Groups enable bulk
  permission management and are included as contextual tuples in authorization
  queries.

- **`iam.miloapis.com/Role`** - Represents role definitions that contain
  collections of permissions. When you create a `Role` CRD, it becomes an object
  of this type in OpenFGA with relationships to specific permissions.

- **`iam.miloapis.com/RoleBinding`** - Acts as an intermediary object that
  connects users, roles, and resources. Every `PolicyBinding` CRD creates a
  RoleBinding instance that establishes the three-way relationship needed for
  authorization.

- **`iam.miloapis.com/Root`** - Represents root-level resource types used for
  ResourceKind policy bindings. This enables system administrators to grant
  permissions across all resources of a specific type, regardless of hierarchy.

- **`iam.miloapis.com/InternalRole`** - Used internally to link RoleBinding
  objects to Role objects. This appears in the `relation` field when connecting
  a role binding to a specific role.

### Authorization Model Example

Below is an example showing how a Role resource type is defined with permissions
that can be granted directly or inherited through parent relationships.

> [!IMPORTANT]
>
> The authorization model below shows the conceptual structure. In the actual
> implementation, permission names are hashed to work within OpenFGA's naming
> constraints.

```yaml
type iam.miloapis.com/Role
  relations
    define granted: [iam.miloapis.com/RoleBinding]
    define parent: [iam.miloapis.com/Organization]
    define iam.miloapis.com/RootBinding: [iam.miloapis.com/Root]

    # Permission relations (shown with full names for clarity)
    define iam.miloapis.com/roles.get: iam.miloapis.com/roles.get from granted or iam.miloapis.com/roles.get from parent
    define iam.miloapis.com/roles.list: iam.miloapis.com/roles.list from granted or iam.miloapis.com/roles.list from parent
    define iam.miloapis.com/roles.create: iam.miloapis.com/roles.create from granted or iam.miloapis.com/roles.create from parent
    define iam.miloapis.com/roles.update: iam.miloapis.com/roles.update from granted or iam.miloapis.com/roles.update from parent
    define iam.miloapis.com/roles.delete: iam.miloapis.com/roles.delete from granted or iam.miloapis.com/roles.delete from parent
```

## Permission Hashing

Permissions are hashed using [FNV-32a hash algorithm][fnv-hash] to create valid
[OpenFGA relation names][relations] while maintaining uniqueness.

[fnv-hash]:
    https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
[relations]: https://openfga.dev/docs/concepts#what-is-a-relation

### Permission Format

Permissions follow the format: `{APIGroup}/{resource}.{verb}`

**Examples**:
- `resourcemanager.miloapis.com/projects.get` → `7fb2c29b`
- `resourcemanager.miloapis.com/projects.list` → `a8d4f3e1`
- `iam.miloapis.com/roles.create` → `f2a8d9e3`

This hashing ensures that:
- Permission names are valid OpenFGA identifiers
- Permissions remain unique across different resource types
- The authorization model stays within OpenFGA's size limits

## Role Management

Roles are managed through [Kubernetes Custom Resources][k8s-custom-resources]
that define collections of permissions. When a Role is created, the system
automatically creates [OpenFGA tuples][tuples] that establish the relationship
between the role and its permissions.

[k8s-custom-resources]:
    https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[tuples]: https://openfga.dev/docs/concepts#what-is-a-tuple

### Role Creation Process

1. **Role CRD Creation**: A `Role` resource is created with a list of
   permissions
2. **Tuple Generation**: The role controller creates tuples linking the role to
   each permission
3. **Universal Availability**: Role permissions are made available to all
   internal users
4. **Binding Activation**: Permissions become effective only when the role is
   bound to users through `PolicyBinding`

### Role Tuple Structure

```yaml
tuples:
- object: iam.miloapis.com/InternalRole:01234567-89ab-cdef-0123-456789abcdef
  relation: 7fb2c29b  # Hash of "resourcemanager.miloapis.com/projects.get"
  user: iam.miloapis.com/InternalUser:*
- object: iam.miloapis.com/InternalRole:01234567-89ab-cdef-0123-456789abcdef
  relation: a8d4f3e1  # Hash of "resourcemanager.miloapis.com/projects.list"
  user: iam.miloapis.com/InternalUser:*
```

**Key Points**:
- **Object**: The role resource identifier
- **Relation**: Hashed permission name
- **User**: Wildcard for all internal users (`*`)
- **Activation**: These tuples only grant access when combined with role
  bindings

### Role Hierarchy

Roles can inherit permissions through the resource hierarchy. If a role grants
`projects.get` permission on an Organization, it automatically includes
`projects.get` on all Projects within that Organization.

## Policy Bindings

Policy bindings are managed through [Kubernetes Custom Resource
Definitions][k8s-crds-concepts] that create relationships between users, roles,
and resources. The system supports multiple types of policy bindings to handle
different authorization scenarios.

[k8s-crds-concepts]:
    https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#customresourcedefinitions

### Standard Policy Bindings

Standard policy bindings grant roles to users on specific resources.

**Creation Process**:

1. **PolicyBinding CRD**: Defines users, roles, and target resources
2. **Role Binding Creation**: Creates an intermediary role binding object
3. **Relationship Tuples**: Establishes three-way relationships

**Tuple Structure**:

```yaml
tuples:
# Link resource to role binding
- object: resourcemanager.miloapis.com/Organization:example-org
  relation: iam.miloapis.com/RoleBinding
  user: iam.miloapis.com/RoleBinding:abcd1234-ef56-7890-abcd-ef1234567890

# Link role binding to role
- object: iam.miloapis.com/RoleBinding:abcd1234-ef56-7890-abcd-ef1234567890
  relation: iam.miloapis.com/InternalRole
  user: iam.miloapis.com/InternalRole:01234567-89ab-cdef-0123-456789abcdef

# Link role binding to user
- object: iam.miloapis.com/RoleBinding:abcd1234-ef56-7890-abcd-ef1234567890
  relation: iam.miloapis.com/InternalUser
  user: iam.miloapis.com/InternalUser:user-uid-12345
```

### ResourceKind Policy Bindings

ResourceKind policy bindings grant roles to users across all resources of a
specific type, regardless of their location in the hierarchy.

**Use Case**: System administrators who need access to all resources of a
particular type.

**Tuple Structure**:

```yaml
tuples:
# Link root resource type to role binding
- object: iam.miloapis.com/Root:resourcemanager.miloapis.com/Organization
  relation: iam.miloapis.com/RoleBinding
  user: iam.miloapis.com/RoleBinding:fedcba09-8765-4321-fedc-ba0987654321

# Link role binding to role and user (same as standard bindings)
- object: iam.miloapis.com/RoleBinding:fedcba09-8765-4321-fedc-ba0987654321
  relation: iam.miloapis.com/InternalRole
  user: iam.miloapis.com/InternalRole:98765432-10ab-cdef-9876-543210fedcba

- object: iam.miloapis.com/RoleBinding:fedcba09-8765-4321-fedc-ba0987654321
  relation: iam.miloapis.com/InternalUser
  user: iam.miloapis.com/InternalUser:admin-uid-67890
```

### Group Memberships

Users can be granted permissions through group memberships, which are managed
through `GroupMembership` CRDs.

**Group Tuple Structure**:

```yaml
tuples:
# User membership in group
- object: iam.miloapis.com/InternalUserGroup:system_authenticated
  relation: member
  user: iam.miloapis.com/InternalUser:user-uid-12345

# Group assigned to role binding
- object: iam.miloapis.com/RoleBinding:grp_i9j0k1l2
  relation: iam.miloapis.com/InternalUser
  user: iam.miloapis.com/InternalUserGroup:system_authenticated
```

**Group Name Escaping**: Colons in group names (like `system:authenticated`) are
escaped to underscores (`system_authenticated`) to ensure valid OpenFGA
identifiers.

## Contextual Tuples

[Contextual tuples][contextual-tuples] are temporary relationships included with
authorization queries to provide additional context that isn't permanently
stored in OpenFGA. They enable complex authorization scenarios without
cluttering the main tuple store.

[contextual-tuples]:
    https://openfga.dev/docs/interacting/relationship-queries#contextual-tuples

### Group Membership Contextual Tuples

When a user makes a request, their group memberships are included as contextual
tuples. The system automatically creates these temporary relationships for
groups that start with `system:` (like `system:authenticated`).

**Example contextual tuple**:
```json
{
  "user": "iam.miloapis.com/InternalUser:user-uid-12345",
  "relation": "member",
  "object": "iam.miloapis.com/InternalUserGroup:system_authenticated"
}
```

**Group Name Processing**: Colons in group names are escaped to underscores
(`system:authenticated` becomes `system_authenticated`) to ensure valid OpenFGA
identifiers.

### Root Binding Contextual Tuples

For ResourceKind policy bindings, contextual tuples link specific resource
instances to their root resource type. This enables system administrators with
ResourceKind bindings to access specific resource instances.

**Example contextual tuple**:
```json
{
  "user": "iam.miloapis.com/Root:resourcemanager.miloapis.com/Organization",
  "relation": "iam.miloapis.com/RootBinding",
  "object": "resourcemanager.miloapis.com/Organization:example-org"
}
```

This contextual tuple allows ResourceKind policy bindings on
`iam.miloapis.com/Root:resourcemanager.miloapis.com/Organization` to grant
permissions on the specific organization `example-org`.

### Parent Resource Contextual Tuples

When resources have parent-child relationships, contextual tuples establish the
hierarchy:

```json
{
  "user": "resourcemanager.miloapis.com/Organization:parent-org",
  "relation": "parent",
  "object": "resourcemanager.miloapis.com/Project:child-project"
}
```

This enables permissions granted on the parent organization to automatically
apply to child projects.

## Resource Hierarchy and Inheritance

The system supports complex resource hierarchies where permissions can be
inherited from parent resources to child resources.

### Hierarchy Definition

Resource hierarchies are defined in `ProtectedResource` [Custom Resource
Definitions][k8s-crd-spec] through the `parentResources` field:

[k8s-crd-spec]:
    https://kubernetes.io/docs/reference/kubernetes-api/extend-resources/custom-resource-definition-v1/

```yaml
apiVersion: iam.miloapis.com/v1alpha1
kind: ProtectedResource
metadata:
  name: projects
spec:
  serviceRef:
    name: resourcemanager.miloapis.com
  kind: Project
  plural: projects
  permissions: ["get", "list", "create", "update", "delete"]
  parentResources:
  - apiGroup: resourcemanager.miloapis.com
    kind: Organization
```

### Inheritance Behavior

**Direct Permissions**: Users with roles on a resource can perform actions
directly on that resource.

**Inherited Permissions**: Users with roles on a parent resource can perform
actions on child resources if:

1. The child resource's `ProtectedResource` declares the parent in
   `parentResources`
2. The parent resource context is included in the authorization request or as a
   tuple in the system
3. The authorization model includes inheritance rules (`from parent`)

### Collection Operations

For collection operations (list, create, watch) where no specific resource name
is provided:

**With Parent Context**: Authorization checks against the parent resource
**Without Parent Context**: Falls back to ResourceKind policy bindings using
root resources

## Troubleshooting

### Common Issues

**Permission Not Found**: Verify that the `ProtectedResource` CRD exists and
includes the requested permission in its `permissions` list.

**Authorization Denied**: Check that:

1. User has appropriate role bindings
2. Role includes the required permission
3. Resource hierarchy is correctly defined
4. Parent context is included for inherited permissions

### Authorization Model Inspection

Use the [OpenFGA CLI][openfga-cli] to inspect the current authorization model:

```bash
# Get current model
fga model get --store-id=01JVTBDT6NJ541P1JBT22GX4PR

# List tuples for debugging
fga tuple read --store-id=01JVTBDT6NJ541P1JBT22GX4PR
```

For installation and usage instructions, see the [OpenFGA CLI
documentation][openfga-cli-docs].

[openfga-cli]: https://github.com/openfga/cli
[openfga-cli-docs]: https://openfga.dev/docs/getting-started/cli

## Related Documentation

- [Architecture](architecture.md) - High-level system design and request
  flow
- [OpenFGA Custom Roles Guide][custom-roles-guide] - Upstream modeling patterns
- [OpenFGA Concepts][openfga-concepts] - Core OpenFGA concepts and terminology
- [Kubernetes Authorization Overview][k8s-authz] - Kubernetes authorization
  concepts
- [Kubernetes Custom Resources][k8s-custom-resources-guide] - Guide to extending
  Kubernetes APIs

[custom-roles-guide]: https://openfga.dev/docs/modeling/custom-roles
[openfga-concepts]: https://openfga.dev/docs/concepts
[k8s-authz]:
    https://kubernetes.io/docs/reference/access-authn-authz/authorization/
[k8s-custom-resources-guide]:
    https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
