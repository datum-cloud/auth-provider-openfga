# Architecture

This document describes how the OpenFGA auth provider integrates with the Milo
APIServer to handle authorization for all API requests made to the Milo
platform.

## Overview

The auth provider acts as a Kubernetes authorization webhook that bridges the
Milo APIServer with OpenFGA's relationship-based authorization engine. When
users access business resources through Milo APIs, the APIServer sends
authorization requests to this webhook, which translates them into OpenFGA
relationship queries.

## Components

### Milo APIServer

The Kubernetes APIServer that serves Milo's business APIs (customers, products,
agreements). The APIServer is configured to use this auth provider as an
authorization webhook.

### Auth Provider Webhook

A Kubernetes service that receives `SubjectAccessReview` requests from the
APIServer and determines whether to allow or deny access based on OpenFGA
relationships.

### OpenFGA Server

The backend authorization service that stores relationship data and evaluates
authorization queries using relationship-based access control.

### Kubernetes Controllers

Controllers that manage authorization configuration through Custom Resource
Definitions (CRDs):
- `ProtectedResource` - Defines which resources require authorization
- `Role` - Defines collections of permissions
- `PolicyBinding` - Creates relationships between users, roles, and resources

## Request Flow

This section describes how authorization requests flow through the system.

### 1. User Makes API Request

A user makes a request to access a business resource through the Milo APIServer:

```
GET /api/resourcemanager.miloapis.com/v1alpha1/organizations/example-org
Authorization: Bearer <token>
```

### 2. APIServer Authentication

The APIServer authenticates the user and extracts:
- User identity and UID
- User groups
- Resource details (API group, resource type, verb, name)
- Context information (parent resources, project scope)

### 3. Authorization Webhook Request

The APIServer sends a `SubjectAccessReview` request to the auth provider
webhook:

```json
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "spec": {
    "user": "user@company.com",
    "uid": "kubernetes-admin",
    "groups": ["authenticated", "sales-team"],
    "extra": {
      "iam.miloapis.com/parent-api-group": ["resourcemanager.miloapis.com"],
      "iam.miloapis.com/parent-type": ["Organization"],
      "iam.miloapis.com/parent-name": ["example-org"]
    },
    "resourceAttributes": {
      "group": "resourcemanager.miloapis.com",
      "resource": "organizations",
      "verb": "get",
      "name": "example-org"
    }
  }
}
```

### 4. Permission Validation

The webhook validates that the requested permission exists by:

1. Querying `ProtectedResource` CRDs to find matching resources
2. Checking if the verb (get, list, create, update, delete) is allowed for the
   resource type

### 5. OpenFGA Authorization Query

The webhook builds an OpenFGA authorization query:

**Query Components:**
- **User**: `iam.miloapis.com/InternalUser:{user-uid}`
- **Resource**: `resourcemanager.miloapis.com/Organization:example-org`
- **Relation**: `{hashed-permission}` (e.g., hash of
  "resourcemanager.miloapis.com/organizations.get")
- **Contextual Tuples**: Group memberships, parent relationships, resource
  bindings

**Example OpenFGA Check Request:**
```json
{
  "store_id": "01JVTBDT6NJ541P1JBT22GX4PR",
  "tuple_key": {
    "user": "iam.miloapis.com/InternalUser:kubernetes-admin",
    "relation": "7fb2c29b89b4",
    "object": "resourcemanager.miloapis.com/Organization:example-org"
  },
  "contextual_tuples": {
    "tuple_keys": [
      {
        "user": "iam.miloapis.com/InternalUser:kubernetes-admin",
        "relation": "member",
        "object": "iam.miloapis.com/Group:sales-team"
      }
    ]
  }
}
```

### 6. Authorization Decision

OpenFGA evaluates the query against stored relationships and returns `allowed:
true/false`.

### 7. Response to APIServer

The webhook returns a `SubjectAccessReview` response:

```json
{
  "apiVersion": "authorization.k8s.io/v1",
  "kind": "SubjectAccessReview",
  "status": {
    "allowed": true,
    "reason": "User has required permissions through role binding"
  }
}
```

### 8. API Request Processing

If authorized, the APIServer processes the original API request and returns the
requested resource data.

## Authorization Scopes

The auth provider supports two authorization scopes to handle different types of
resources and access patterns.

### Core Control Plane

**Endpoint**: `/core/v1alpha/webhook`

**Purpose**: Authorizes access to system-wide resources like users, roles, and
organization-level resources.

**Resource Targeting**:
- For specific resources: Uses the actual resource name
  (`resourcemanager.miloapis.com/Organization:example-org`)
- For collection operations: Uses parent resource from request context or falls
  back to root resource
  (`iam.miloapis.com/Root:resourcemanager.miloapis.com/Organization`)

### Project Control Plane

**Endpoint**: `/project/v1alpha/projects/{project}/webhook`

**Purpose**: Authorizes access to project-scoped resources with tenant
isolation.

**Resource Targeting**: Always uses the project resource
(`resourcemanager.miloapis.com/Project:project-name`) as the authorization
target.

**Project Resolution**: Extracts project identifier from the webhook URL path
and resolves it to the actual Kubernetes Project resource.

## Webhook Configuration

### APIServer Integration

The OpenFGA auth provider's webhook supports managing authorization using the
Kubernetes APIServer webhook authorization integration. See the [Kuberentes
authorization][kube-authz] documentation for more information.

[kube-authz]:
    https://kubernetes.io/docs/reference/access-authn-authz/authorization/

## Monitoring and Observability

### Metrics

- Exposes [controller-runtime metrics] via Prometheus to provide visibility on
  controllers and webhook requests

[controller-runtime metrics]:
    https://book.kubebuilder.io/reference/metrics-reference

## Related Documentation

- [OpenFGA Integration](openfga-integration.md) - Detailed OpenFGA
  implementation
