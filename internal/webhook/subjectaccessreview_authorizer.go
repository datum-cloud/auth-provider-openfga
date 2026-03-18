package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"go.miloapis.com/auth-provider-openfga/internal/openfga"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/discovery"
)

const (
	SubjectAccessReviewWebhookPath = "/apis/authorization.k8s.io/v1/subjectaccessreviews"
)

// WebhookServer interface abstracts the webhook server registration
type WebhookServer interface {
	Register(path string, hook http.Handler)
}

// Contains a mapping of Kubernetes APIGroups to the service name that should be
// used by the webhook to perform authorization checks.
var serviceNameMapping = map[string]string{
	// An empty APIGroup is used for the core/v1 Kubernetes API Group.
	"": "core.miloapis.com",
}

var _ authorizer.Authorizer = &SubjectAccessReviewAuthorizer{}

type SubjectAccessReviewAuthorizer struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	// AuthorizationModelID pins every CheckRequest to a specific authorization
	// model. When set, OpenFGA skips its internal model lookup (one DB read
	// saved per Check call). If empty, OpenFGA resolves the latest model on
	// each call (safe but slower).
	AuthorizationModelID   string
	ProtectedResourceCache *ProtectedResourceCache
	DiscoveryClient        discovery.DiscoveryInterface
	// SystemGroupMaterializer persists system group membership tuples to OpenFGA
	// on first encounter so that OpenFGA's check query cache can resolve them.
	// If nil, system group tuples are not written (useful in tests that do not
	// exercise this path).
	SystemGroupMaterializer *SystemGroupMaterializer
}

// Config holds the configuration for creating a SubjectAccessReview webhook
type Config struct {
	FGAClient  openfgav1.OpenFGAServiceClient
	FGAStoreID string
	// AuthorizationModelID pins CheckRequests to a specific model, eliminating
	// the per-request model lookup in OpenFGA. Leave empty to use the latest.
	AuthorizationModelID   string
	ProtectedResourceCache *ProtectedResourceCache
	DiscoveryClient        discovery.DiscoveryInterface
}

// NewSubjectAccessReviewWebhook creates a new SubjectAccessReview authorization webhook
func NewSubjectAccessReviewWebhook(config Config) *Webhook {
	authorizer := &SubjectAccessReviewAuthorizer{
		FGAClient:               config.FGAClient,
		FGAStoreID:              config.FGAStoreID,
		AuthorizationModelID:    config.AuthorizationModelID,
		ProtectedResourceCache:  config.ProtectedResourceCache,
		DiscoveryClient:         config.DiscoveryClient,
		SystemGroupMaterializer: NewSystemGroupMaterializer(config.FGAClient, config.FGAStoreID),
	}
	return NewAuthorizerWebhook(authorizer)
}

// RegisterSubjectAccessReviewWebhook registers a SubjectAccessReview webhook with the provided server
// This fully encapsulates the webhook registration details within the webhook package
func RegisterSubjectAccessReviewWebhook(server WebhookServer, config Config) {
	webhook := NewSubjectAccessReviewWebhook(config)
	server.Register(SubjectAccessReviewWebhookPath, webhook)
}

// parentContext represents the parent resource context from user extra data
type parentContext struct {
	apiGroup string
	kind     string
	name     string
}

// authorizationContext holds the essential information needed for authorization
type authorizationContext struct {
	userUID       string
	permission    string
	parentContext *parentContext
	namespace     string
}

// isProjectScope checks if the parent context is a Project resource
func (ctx *authorizationContext) isProjectScope() bool {
	return ctx.parentContext != nil &&
		ctx.parentContext.apiGroup == "resourcemanager.miloapis.com" &&
		ctx.parentContext.kind == "Project"
}

// isOrganizationScope checks if the parent context is an Organization resource
func (ctx *authorizationContext) isOrganizationScope() bool {
	return ctx.parentContext != nil &&
		ctx.parentContext.apiGroup == "resourcemanager.miloapis.com" &&
		ctx.parentContext.kind == "Organization"
}

// getProjectName returns the project name if in project scope
func (ctx *authorizationContext) getProjectName() string {
	if ctx.isProjectScope() {
		return ctx.parentContext.name
	}
	return ""
}

// getOrganizationName returns the organization name if in organization scope
func (ctx *authorizationContext) getOrganizationName() string {
	if ctx.isOrganizationScope() {
		return ctx.parentContext.name
	}
	return ""
}

// scopeLabel returns the metric scope label for an authorization context.
func scopeLabel(authCtx *authorizationContext) string {
	if authCtx == nil {
		return "unknown"
	}
	if authCtx.isProjectScope() {
		return "project"
	}
	if authCtx.isOrganizationScope() {
		return "organization"
	}
	return "cluster"
}

// extractParentContext extracts parent resource information from user extra data
func (o *SubjectAccessReviewAuthorizer) extractParentContext(attributes authorizer.Attributes) *parentContext {
	extra := attributes.GetUser().GetExtra()

	parentAPIGroup, apiGroupOK := extra[iamv1alpha1.ParentAPIGroupExtraKey]
	parentKind, kindOK := extra[iamv1alpha1.ParentKindExtraKey]
	parentName, nameOK := extra[iamv1alpha1.ParentNameExtraKey]

	if !apiGroupOK || !kindOK || !nameOK {
		return nil
	}

	if len(parentAPIGroup) == 1 && len(parentKind) == 1 && len(parentName) == 1 {
		return &parentContext{
			apiGroup: parentAPIGroup[0],
			kind:     parentKind[0],
			name:     parentName[0],
		}
	}

	return nil
}

// Authorize implements authorizer.Authorizer.
func (o *SubjectAccessReviewAuthorizer) Authorize(ctx context.Context, attributes authorizer.Attributes) (authorizer.Decision, string, error) {
	start := time.Now()
	requestID := requestIDFromContext(ctx)
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")

	ctx, span := tracer.Start(ctx, "authorize")
	defer span.End()

	span.SetAttributes(
		attribute.String("authz.user", attributes.GetUser().GetName()),
		attribute.String("authz.resource", attributes.GetResource()),
		attribute.String("authz.verb", attributes.GetVerb()),
		attribute.String("authz.resource_group", attributes.GetAPIGroup()),
	)

	// Step 1: Build authorization context
	stepStart := time.Now()
	ctx, buildCtxSpan := tracer.Start(ctx, "build_authorization_context")
	authCtx, err := o.buildAuthorizationContext(attributes)
	buildCtxSpan.End()
	authzStepDuration.WithLabelValues("build_context").Observe(time.Since(stepStart).Seconds())
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return authorizer.DecisionDeny, "", err
	}

	scope := scopeLabel(authCtx)
	span.SetAttributes(attribute.String("authz.scope", scope))

	// Step 2: Materialize system group memberships as stored tuples so that
	// OpenFGA's check query cache can resolve them. This is a best-effort
	// optimization; a write failure is logged but does not block the request.
	if o.SystemGroupMaterializer != nil {
		if materializeErr := o.SystemGroupMaterializer.EnsureMaterialized(
			ctx,
			authCtx.userUID,
			attributes.GetUser().GetGroups(),
		); materializeErr != nil {
			slog.WarnContext(ctx, "failed to materialize system group memberships; proceeding without stored tuples",
				slog.String("user_uid", authCtx.userUID),
				slog.String("error", materializeErr.Error()),
				slog.String("request_id", requestID),
			)
		}
	}

	// Step 4: Validate organization namespace if organization-scoped
	stepStart = time.Now()
	ctx, validateNsSpan := tracer.Start(ctx, "validate_organization_namespace")
	validateNsErr := o.validateOrganizationNamespace(ctx, authCtx, attributes)
	validateNsSpan.End()
	authzStepDuration.WithLabelValues("validate_namespace").Observe(time.Since(stepStart).Seconds())
	if validateNsErr != nil {
		slog.WarnContext(ctx, "organization namespace validation failed",
			slog.String("error", validateNsErr.Error()),
			slog.String("request_id", requestID),
		)
		span.RecordError(validateNsErr)
		span.SetStatus(codes.Error, validateNsErr.Error())
		return authorizer.DecisionDeny, "", validateNsErr
	}

	// Step 5: Validate permission exists
	stepStart = time.Now()
	ctx, validatePermSpan := tracer.Start(ctx, "validate_permission")
	validatePermErr := o.validatePermission(ctx, attributes)
	validatePermSpan.End()
	authzStepDuration.WithLabelValues("validate_permission").Observe(time.Since(stepStart).Seconds())
	if validatePermErr != nil {
		span.RecordError(validatePermErr)
		span.SetStatus(codes.Error, validatePermErr.Error())
		return authorizer.DecisionDeny, "", validatePermErr
	}

	// Step 6: Build OpenFGA check request
	stepStart = time.Now()
	ctx, buildReqSpan := tracer.Start(ctx, "build_openfga_request")
	checkReq, err := o.buildOpenFGARequest(ctx, attributes, authCtx)
	buildReqSpan.End()
	authzStepDuration.WithLabelValues("build_openfga_request").Observe(time.Since(stepStart).Seconds())
	if err != nil {
		buildErr := fmt.Errorf("failed to build OpenFGA request: %w", err)
		span.RecordError(buildErr)
		span.SetStatus(codes.Error, buildErr.Error())
		return authorizer.DecisionDeny, "", buildErr
	}

	// Step 7: Execute OpenFGA check
	stepStart = time.Now()
	decision, reason, checkErr := o.executeOpenFGACheck(ctx, checkReq)
	authzStepDuration.WithLabelValues("openfga_check").Observe(time.Since(stepStart).Seconds())

	// Record total end-to-end duration at the authorizer level as well, labeled
	// with the decision and scope so it can be used independently of the HTTP
	// handler metrics.
	totalDuration := time.Since(start)
	decisionStr := decisionLabel(decision, checkErr)
	resourceGroup := attributes.GetAPIGroup()

	authzRequestDuration.WithLabelValues(decisionStr, scope, resourceGroup).Observe(totalDuration.Seconds())
	authzDecisionsTotal.WithLabelValues(decisionStr, scope, resourceGroup).Inc()

	span.SetAttributes(attribute.String("authz.decision", decisionStr))
	if checkErr != nil {
		span.RecordError(checkErr)
		span.SetStatus(codes.Error, checkErr.Error())
	}

	slog.InfoContext(ctx, "authorization completed",
		slog.String("request_id", requestID),
		slog.String("traceID", traceIDFromSpan(span)),
		slog.Duration("duration", totalDuration),
		slog.String("decision", decisionStr),
		slog.String("scope", scope),
		slog.String("resource_group", resourceGroup),
		slog.String("resource", attributes.GetResource()),
		slog.String("verb", attributes.GetVerb()),
		slog.String("user", attributes.GetUser().GetName()),
	)

	return decision, reason, checkErr
}

// decisionLabel maps an authorizer.Decision and optional error to the metric
// label used on authz_request_duration_seconds and authz_decisions_total.
func decisionLabel(decision authorizer.Decision, err error) string {
	if err != nil {
		return "error"
	}
	switch decision {
	case authorizer.DecisionAllow:
		return "allowed"
	case authorizer.DecisionDeny:
		return "denied"
	default:
		return "no_opinion"
	}
}

// buildAuthorizationContext extracts and validates the essential information needed for authorization
func (o *SubjectAccessReviewAuthorizer) buildAuthorizationContext(attributes authorizer.Attributes) (*authorizationContext, error) {
	userUID := attributes.GetUser().GetUID()
	if userUID == "" {
		return nil, fmt.Errorf("user UID is required by SubjectAccessReview authorizer")
	}

	permission := o.buildPermissionString(attributes)
	parentContext := o.extractParentContext(attributes)
	namespace := attributes.GetNamespace()

	return &authorizationContext{
		userUID:       userUID,
		permission:    permission,
		parentContext: parentContext,
		namespace:     namespace,
	}, nil
}

// isResourceNamespaced determines if a given resource type is namespace-scoped using Kubernetes API discovery
// Uses a TTL-based cached discovery client that automatically refreshes stale cache entries
func (o *SubjectAccessReviewAuthorizer) isResourceNamespaced(ctx context.Context, apiGroup, apiVersion, resource string) (bool, error) {
	// Build the full group version string for discovery
	var groupVersion string
	if apiGroup == "" {
		// Core API group - use version directly
		groupVersion = apiVersion
	} else {
		// Named API group - combine group and version
		groupVersion = fmt.Sprintf("%s/%s", apiGroup, apiVersion)
	}

	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, discoverySpan := tracer.Start(ctx, "k8s.discovery.ServerResourcesForGroupVersion")
	discoverySpan.SetAttributes(attribute.String("api.group_version", groupVersion))

	// Get server resources for the API group version
	// The cached discovery client handles TTL-based refresh automatically
	stepStart := time.Now()
	resourceList, err := o.DiscoveryClient.ServerResourcesForGroupVersion(groupVersion)
	discoveryDuration := time.Since(stepStart)
	discoverySpan.End()

	authzStepDuration.WithLabelValues("k8s_discovery").Observe(discoveryDuration.Seconds())

	if err != nil {
		authzK8sAPICallsTotal.WithLabelValues("discovery", "get", "error").Inc()
		slog.WarnContext(ctx, "failed to get server resources",
			slog.String("apiGroup", apiGroup),
			slog.String("apiVersion", apiVersion),
			slog.String("groupVersion", groupVersion),
			slog.String("error", err.Error()))
		return false, fmt.Errorf("failed to get server resources for group version %s: %w", groupVersion, err)
	}
	authzK8sAPICallsTotal.WithLabelValues("discovery", "get", "success").Inc()

	slog.DebugContext(ctx, "k8s discovery completed",
		slog.String("group_version", groupVersion),
		slog.Duration("duration", discoveryDuration),
	)

	// Find the resource in the list
	for _, apiResource := range resourceList.APIResources {
		if apiResource.Name == resource {
			slog.DebugContext(ctx, "found resource in discovery cache",
				slog.String("apiGroup", apiGroup),
				slog.String("apiVersion", apiVersion),
				slog.String("resource", resource),
				slog.Bool("namespaced", apiResource.Namespaced))
			return apiResource.Namespaced, nil
		}
	}

	// Resource not found - this could indicate a new resource that hasn't been cached yet
	slog.WarnContext(ctx, "resource not found in API group version, this may indicate a newly registered resource",
		slog.String("apiGroup", apiGroup),
		slog.String("apiVersion", apiVersion),
		slog.String("groupVersion", groupVersion),
		slog.String("resource", resource))
	return false, fmt.Errorf("resource %s not found in API group version %s", resource, groupVersion)
}

// validateOrganizationNamespace ensures the request namespace matches the organization's namespace
func (o *SubjectAccessReviewAuthorizer) validateOrganizationNamespace(ctx context.Context, authCtx *authorizationContext, attributes authorizer.Attributes) error {
	if !authCtx.isOrganizationScope() {
		return nil // Not organization-scoped, skip validation
	}

	requestNamespace := attributes.GetNamespace()
	expectedNamespace := fmt.Sprintf("organization-%s", authCtx.getOrganizationName())

	// If no namespace specified in request, check if resource is cluster-scoped
	if requestNamespace == "" {
		isNamespaced, err := o.isResourceNamespaced(ctx, attributes.GetAPIGroup(), attributes.GetAPIVersion(), attributes.GetResource())
		if err != nil {
			return fmt.Errorf("failed to determine if resource is namespaced: %w", err)
		}

		if !isNamespaced {
			// Cluster-scoped resource - no namespace validation needed
			return nil
		}

		// Namespace-scoped resource with empty namespace = cross-namespace query
		// Deny for organization-scoped requests
		return fmt.Errorf("cross-namespace queries not allowed for organization-scoped requests")
	}

	// Namespace specified - validate it matches organization's namespace
	if requestNamespace != expectedNamespace {
		return fmt.Errorf("namespace mismatch: request namespace '%s' does not match organization namespace '%s'",
			requestNamespace, expectedNamespace)
	}

	return nil
}

// validatePermission checks if the requested permission is registered
func (o *SubjectAccessReviewAuthorizer) validatePermission(ctx context.Context, attributes authorizer.Attributes) error {
	permissionExists, err := o.validatePermissionWithServiceDefaulting(ctx, attributes)
	if err != nil {
		slog.ErrorContext(ctx, "failed to validate permission", slog.String("error", err.Error()))
		return fmt.Errorf("failed to validate permission: %w", err)
	}

	if !permissionExists {
		permission := o.buildPermissionString(attributes)
		slog.WarnContext(ctx, "permission not found", slog.Any("attributes", attributes), slog.String("permission", permission))
		return fmt.Errorf("permission '%s' not registered", permission)
	}

	return nil
}

// executeOpenFGACheck performs the OpenFGA authorization check
func (o *SubjectAccessReviewAuthorizer) executeOpenFGACheck(ctx context.Context, checkReq *openfgav1.CheckRequest) (authorizer.Decision, string, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, checkSpan := tracer.Start(ctx, "openfga.check")
	checkSpan.SetAttributes(
		attribute.String("openfga.store_id", o.FGAStoreID),
		attribute.String("openfga.user", checkReq.TupleKey.User),
		attribute.String("openfga.relation", checkReq.TupleKey.Relation),
		attribute.String("openfga.object", checkReq.TupleKey.Object),
	)
	defer checkSpan.End()

	slog.InfoContext(ctx, "checking OpenFGA authorization",
		slog.String("user", checkReq.TupleKey.User),
		slog.String("resource", checkReq.TupleKey.Object),
		slog.String("relation", checkReq.TupleKey.Relation),
		slog.Any("contextual_tuples", checkReq.ContextualTuples),
	)

	resp, err := o.FGAClient.Check(ctx, checkReq)
	if err != nil {
		openfgaCheckTotal.WithLabelValues("false", "true").Inc()
		checkSpan.RecordError(err)
		checkSpan.SetStatus(codes.Error, err.Error())
		slog.ErrorContext(ctx, "failed to check authorization in OpenFGA", slog.String("error", err.Error()))
		return authorizer.DecisionNoOpinion, "", err
	}

	allowed := resp.GetAllowed()
	openfgaCheckTotal.WithLabelValues(strconv.FormatBool(allowed), "false").Inc()
	checkSpan.SetAttributes(attribute.Bool("openfga.allowed", allowed))

	if allowed {
		slog.DebugContext(ctx, "subject was granted access through OpenFGA")
		return authorizer.DecisionAllow, "", nil
	}

	return authorizer.DecisionDeny, "", nil
}

// buildOpenFGARequest creates the appropriate OpenFGA check request based on the authorization context
func (o *SubjectAccessReviewAuthorizer) buildOpenFGARequest(ctx context.Context, attributes authorizer.Attributes, authCtx *authorizationContext) (*openfgav1.CheckRequest, error) {
	user := fmt.Sprintf("iam.miloapis.com/InternalUser:%s", authCtx.userUID)
	relation := o.buildHashedPermissionRelation(attributes)

	var resource string
	var contextualTuples []*openfgav1.TupleKey

	if authCtx.isProjectScope() {
		// Project-scoped authorization: authorize against the project resource
		resource = fmt.Sprintf("resourcemanager.miloapis.com/Project:%s", authCtx.getProjectName())
		rootResourceType := "resourcemanager.miloapis.com/Project"
		contextualTuples = buildAllContextualTuples(attributes, rootResourceType, resource)
	} else {
		// Regular authorization: build resource and contextual tuples based on request type
		var err error
		resource, contextualTuples, err = o.buildResourceAndContextualTuples(ctx, attributes)
		if err != nil {
			return nil, err
		}
	}

	checkReq := &openfgav1.CheckRequest{
		StoreId:              o.FGAStoreID,
		AuthorizationModelId: o.AuthorizationModelID,
		TupleKey: &openfgav1.CheckRequestTupleKey{
			User:     user,
			Relation: relation,
			Object:   resource,
		},
	}

	if len(contextualTuples) > 0 {
		checkReq.ContextualTuples = &openfgav1.ContextualTupleKeys{
			TupleKeys: contextualTuples,
		}
	}

	return checkReq, nil
}

// validatePermissionWithServiceDefaulting validates permissions with consistent service name defaulting.
// It uses the in-memory ProtectedResourceCache for O(1) lookups instead of a K8s API List call.
func (o *SubjectAccessReviewAuthorizer) validatePermissionWithServiceDefaulting(ctx context.Context, attributes authorizer.Attributes) (bool, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, cacheSpan := tracer.Start(ctx, "cache.get.ProtectedResource/validatePermission")
	defer cacheSpan.End()

	apiGroup := o.getEffectiveAPIGroup(attributes)
	resource := attributes.GetResource()
	verb := attributes.GetVerb()

	stepStart := time.Now()
	pr, ok := o.ProtectedResourceCache.GetByAPIGroupAndResource(apiGroup, resource)
	duration := time.Since(stepStart)

	authzStepDuration.WithLabelValues("protectedresource_cache_lookup").Observe(duration.Seconds())

	if ok {
		authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "hit").Inc()
		slog.DebugContext(ctx, "protectedresource cache hit (validatePermission)",
			slog.String("apiGroup", apiGroup),
			slog.String("resource", resource),
			slog.Duration("duration", duration),
		)
		return slices.Contains(pr.Spec.Permissions, verb), nil
	}

	authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "miss").Inc()
	slog.DebugContext(ctx, "protectedresource cache miss (validatePermission)",
		slog.String("apiGroup", apiGroup),
		slog.String("resource", resource),
		slog.Duration("duration", duration),
	)
	return false, nil
}

// getEffectiveAPIGroup returns the API group with service name mapping applied consistently
func (o *SubjectAccessReviewAuthorizer) getEffectiveAPIGroup(attributes authorizer.Attributes) string {
	apiGroup := attributes.GetAPIGroup()

	// Apply service name mapping for any api groups that need adjusting before
	// building the permission string.
	if override, exists := serviceNameMapping[apiGroup]; exists {
		return override
	}

	return apiGroup
}

// buildPermissionString constructs the permission string in the format: service/resource.verb
func (o *SubjectAccessReviewAuthorizer) buildPermissionString(attributes authorizer.Attributes) string {
	apiGroup := o.getEffectiveAPIGroup(attributes)
	resource := attributes.GetResource()
	verb := attributes.GetVerb()
	return fmt.Sprintf("%s/%s.%s", apiGroup, resource, verb)
}

func (o *SubjectAccessReviewAuthorizer) buildParentResource(attributes authorizer.Attributes) (string, error) {
	extra := attributes.GetUser().GetExtra()

	// If a parent is in the context, add a tuple for its parent relationship
	parentAPIGroup, parentAPIGroupOK := extra[iamv1alpha1.ParentAPIGroupExtraKey]
	parentKind, parentKindOK := extra[iamv1alpha1.ParentKindExtraKey]
	parentName, parentNameOK := extra[iamv1alpha1.ParentNameExtraKey]

	if parentAPIGroupOK && parentKindOK && parentNameOK {
		if len(parentAPIGroup) == 1 && len(parentKind) == 1 && len(parentName) == 1 {
			return fmt.Sprintf("%s/%s:%s", parentAPIGroup[0], parentKind[0], parentName[0]), nil
		}
	}

	return "", fmt.Errorf("parent resource not found in extra data")
}

// buildRootResource constructs a root resource string for ResourceKind policy bindings
// when no parent resource is available in the request context
func (o *SubjectAccessReviewAuthorizer) buildRootResource(protectedResource *iamv1alpha1.ProtectedResource) string {
	// Root resource format: "iam.miloapis.com/Root:{resource_type}"
	// where resource_type is "{APIGroup}/{Kind}" format used by the authorization model
	resourceType := fmt.Sprintf("%s/%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind)
	return fmt.Sprintf("iam.miloapis.com/Root:%s", resourceType)
}

func (o *SubjectAccessReviewAuthorizer) buildParentResourceType(attributes authorizer.Attributes) (string, error) {
	// Extract parent resource type from the extra data
	user := attributes.GetUser()
	extra := user.GetExtra()

	parentAPIGroup, ok := extra["iam.miloapis.com/parent-api-group"]
	if !ok || len(parentAPIGroup) == 0 {
		return "", fmt.Errorf("missing iam.miloapis.com/parent-api-group in extra data")
	}

	parentType, ok := extra["iam.miloapis.com/parent-type"]
	if !ok || len(parentType) == 0 {
		return "", fmt.Errorf("missing iam.miloapis.com/parent-type in extra data")
	}

	return fmt.Sprintf("%s/%s", parentAPIGroup[0], parentType[0]), nil
}

// buildResourceAndContextualTuples builds the resource identifier and contextual tuples for regular (non-project) authorization
func (o *SubjectAccessReviewAuthorizer) buildResourceAndContextualTuples(ctx context.Context, attributes authorizer.Attributes) (string, []*openfgav1.TupleKey, error) {
	// Get the ProtectedResource to understand the correct resource structure
	protectedResource, err := o.getProtectedResource(ctx, attributes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get protected resource: %w", err)
	}

	// Handle collection operations (list, create, watch) or requests without specific resource name
	if slices.Contains([]string{"list", "create", "watch"}, attributes.GetVerb()) || attributes.GetName() == "" {
		return o.buildCollectionResourceAndTuples(attributes, protectedResource)
	}

	// Handle specific resource operations (get, update, delete, patch)
	return o.buildSpecificResourceAndTuples(attributes, protectedResource)
}

// buildCollectionResourceAndTuples handles collection operations like list, create, watch
func (o *SubjectAccessReviewAuthorizer) buildCollectionResourceAndTuples(attributes authorizer.Attributes, protectedResource *iamv1alpha1.ProtectedResource) (string, []*openfgav1.TupleKey, error) {
	// Try to get parent resource from context first
	parentResource, err := o.buildParentResource(attributes)
	if err != nil {
		// Fallback to using root resource for ResourceKind policy bindings
		rootResource := o.buildRootResource(protectedResource)
		groupTuples := buildGroupContextualTuples(attributes)
		return rootResource, groupTuples, nil
	}

	// Using parent resource - build all contextual tuples
	parentResourceType, err := o.buildParentResourceType(attributes)
	if err != nil {
		// If we can't determine parent type, use only group tuples
		groupTuples := buildGroupContextualTuples(attributes)
		return parentResource, groupTuples, nil
	}

	contextualTuples := buildAllContextualTuples(attributes, parentResourceType, parentResource)
	return parentResource, contextualTuples, nil
}

// buildSpecificResourceAndTuples handles specific resource operations like get, update, delete
func (o *SubjectAccessReviewAuthorizer) buildSpecificResourceAndTuples(attributes authorizer.Attributes, protectedResource *iamv1alpha1.ProtectedResource) (string, []*openfgav1.TupleKey, error) {
	// Build the fully qualified resource identifier
	resource := fmt.Sprintf("%s/%s:%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind, attributes.GetName())

	// Start with root binding and group tuples
	rootResourceType := fmt.Sprintf("%s/%s", protectedResource.Spec.ServiceRef.Name, protectedResource.Spec.Kind)
	rootBindingTuple := buildRootBindingContextualTuple(rootResourceType, resource)
	groupTuples := buildGroupContextualTuples(attributes)

	contextualTuples := []*openfgav1.TupleKey{rootBindingTuple}
	contextualTuples = append(contextualTuples, groupTuples...)

	// Add parent tuple if parent resource is registered
	parentResource, err := o.buildParentResource(attributes)
	if err == nil && o.isParentResourceRegistered(protectedResource, parentResource) {
		parentTuple := &openfgav1.TupleKey{
			User:     parentResource,
			Relation: "parent",
			Object:   resource,
		}
		contextualTuples = append(contextualTuples, parentTuple)
	}

	return resource, contextualTuples, nil
}

// buildHashedPermissionRelation builds a hashed permission relation for OpenFGA
func (o *SubjectAccessReviewAuthorizer) buildHashedPermissionRelation(attributes authorizer.Attributes) string {
	// Build permission in the format expected by OpenFGA: service/resource.verb
	permission := o.buildPermissionString(attributes)

	// Hash the permission to match the OpenFGA model
	hashedPermission := openfga.HashPermission(permission)
	slog.Debug("buildRelation",
		slog.String("permission", permission),
		slog.String("hashedPermission", hashedPermission),
		slog.String("apiGroup", attributes.GetAPIGroup()),
		slog.String("resource", attributes.GetResource()),
		slog.String("verb", attributes.GetVerb()),
	)
	return hashedPermission
}

// getProtectedResource retrieves the ProtectedResource for the given attributes.
// It uses the in-memory ProtectedResourceCache for O(1) lookups instead of a K8s API List call.
func (o *SubjectAccessReviewAuthorizer) getProtectedResource(ctx context.Context, attributes authorizer.Attributes) (*iamv1alpha1.ProtectedResource, error) {
	tracer := otel.GetTracerProvider().Tracer("authz-webhook")
	ctx, cacheSpan := tracer.Start(ctx, "cache.get.ProtectedResource/buildRequest")
	defer cacheSpan.End()

	apiGroup := attributes.GetAPIGroup()
	resource := attributes.GetResource()

	stepStart := time.Now()
	pr, ok := o.ProtectedResourceCache.GetByAPIGroupAndResource(apiGroup, resource)
	duration := time.Since(stepStart)

	authzStepDuration.WithLabelValues("protectedresource_cache_lookup").Observe(duration.Seconds())

	if ok {
		authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "hit").Inc()
		slog.DebugContext(ctx, "protectedresource cache hit (buildRequest)",
			slog.String("apiGroup", apiGroup),
			slog.String("resource", resource),
			slog.Duration("duration", duration),
		)
		return pr, nil
	}

	authzK8sAPICallsTotal.WithLabelValues("protectedresources", "cache_get", "miss").Inc()
	slog.DebugContext(ctx, "protectedresource cache miss (buildRequest)",
		slog.String("apiGroup", apiGroup),
		slog.String("resource", resource),
		slog.Duration("duration", duration),
	)
	return nil, fmt.Errorf("no ProtectedResource found for APIGroup=%s, Resource=%s", apiGroup, resource)
}

// isParentResourceRegistered checks if the given parent resource type is registered
// in the ProtectedResource's ParentResources list
func (o *SubjectAccessReviewAuthorizer) isParentResourceRegistered(protectedResource *iamv1alpha1.ProtectedResource, parentResource string) bool {
	// Extract the parent resource type from the parent resource string
	// Parent resource format: "{APIGroup}/{Kind}:{Name}" (e.g., "resourcemanager.miloapis.com/Organization:org-123")
	// We need to extract the "{APIGroup}/{Kind}" part
	parts := strings.Split(parentResource, ":")
	if len(parts) != 2 {
		return false
	}
	parentResourceType := parts[0] // This is "{APIGroup}/{Kind}"

	// Split the parent resource type into APIGroup and Kind
	typeParts := strings.Split(parentResourceType, "/")
	if len(typeParts) != 2 {
		return false
	}
	parentAPIGroup := typeParts[0]
	parentKind := typeParts[1]

	// Check if this parent resource type is registered in the ProtectedResource
	for _, parentRef := range protectedResource.Spec.ParentResources {
		if parentRef.APIGroup == parentAPIGroup && parentRef.Kind == parentKind {
			return true
		}
	}

	return false
}
