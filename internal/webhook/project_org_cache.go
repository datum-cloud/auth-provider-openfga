package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	toolscache "k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
)

// ProjectOrganizationCache maintains an in-memory index mapping project names
// to their parent organization names, populated and kept up to date by a
// controller-runtime informer.
//
// This allows the authorization webhook to fan out project-scoped checks into
// two parallel OpenFGA calls (one against the project, one against the org)
// without paying the cost of OpenFGA's sequential graph traversal through the
// project → org parent tuple chain.
type ProjectOrganizationCache struct {
	mu sync.RWMutex
	// index maps project name to parent organization name
	index map[string]string
}

// NewProjectOrganizationCache creates a ProjectOrganizationCache and registers
// event handlers on the manager's informer for Project resources. The cache
// starts empty and is populated once the manager's cache syncs — callers must
// ensure the manager is started before serving requests.
func NewProjectOrganizationCache(ctx context.Context, mgr ctrl.Manager) (*ProjectOrganizationCache, error) {
	c := &ProjectOrganizationCache{
		index: make(map[string]string),
	}

	informer, err := mgr.GetCache().GetInformer(ctx, &resourcemanagerv1alpha1.Project{})
	if err != nil {
		return nil, fmt.Errorf("failed to get Project informer: %w", err)
	}

	if _, err := informer.AddEventHandler(toolscache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			project, ok := obj.(*resourcemanagerv1alpha1.Project)
			if !ok {
				return
			}
			c.upsert(project)
		},
		UpdateFunc: func(_, newObj interface{}) {
			project, ok := newObj.(*resourcemanagerv1alpha1.Project)
			if !ok {
				return
			}
			c.upsert(project)
		},
		DeleteFunc: func(obj interface{}) {
			project, ok := obj.(*resourcemanagerv1alpha1.Project)
			if !ok {
				// Handle tombstone objects that the informer emits when an item is
				// deleted but only the key is available.
				tombstone, ok := obj.(toolscache.DeletedFinalStateUnknown)
				if !ok {
					slog.Warn("project_org_cache: unexpected object type in DeleteFunc",
						slog.String("type", fmt.Sprintf("%T", obj)))
					return
				}
				project, ok = tombstone.Obj.(*resourcemanagerv1alpha1.Project)
				if !ok {
					slog.Warn("project_org_cache: unexpected tombstone object type",
						slog.String("type", fmt.Sprintf("%T", tombstone.Obj)))
					return
				}
			}
			c.delete(project)
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to add event handler to Project informer: %w", err)
	}

	return c, nil
}

// WaitForCacheSync blocks until the informer cache has synced. It should be
// called after the manager has started and before the cache is used to serve
// requests.
func (c *ProjectOrganizationCache) WaitForCacheSync(ctx context.Context, mgrCache cache.Cache) error {
	if !mgrCache.WaitForCacheSync(ctx) {
		return fmt.Errorf("timed out waiting for Project cache to sync")
	}
	return nil
}

// GetOrganizationForProject returns the parent organization name for a given
// project name. The second return value is false when no matching entry exists
// (project is not cached or has no organization owner).
func (c *ProjectOrganizationCache) GetOrganizationForProject(projectName string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	org, ok := c.index[projectName]
	return org, ok
}

func (c *ProjectOrganizationCache) upsert(project *resourcemanagerv1alpha1.Project) {
	orgName := project.Spec.OwnerRef.Name
	if orgName == "" {
		// Project has no owner org yet — remove any stale entry so we don't
		// make authorization decisions based on outdated data.
		c.mu.Lock()
		delete(c.index, project.Name)
		c.mu.Unlock()
		slog.Debug("project_org_cache: skipped project with empty ownerRef.name",
			slog.String("project", project.Name))
		return
	}

	c.mu.Lock()
	c.index[project.Name] = orgName
	c.mu.Unlock()

	slog.Debug("project_org_cache: upserted entry",
		slog.String("project", project.Name),
		slog.String("organization", orgName),
	)
}

func (c *ProjectOrganizationCache) delete(project *resourcemanagerv1alpha1.Project) {
	c.mu.Lock()
	delete(c.index, project.Name)
	c.mu.Unlock()
	slog.Debug("project_org_cache: deleted entry",
		slog.String("project", project.Name),
	)
}

// newProjectOrganizationCacheFromItems creates a ProjectOrganizationCache
// pre-populated with the provided items. This is intended for use in tests only.
func newProjectOrganizationCacheFromItems(items []resourcemanagerv1alpha1.Project) *ProjectOrganizationCache {
	c := &ProjectOrganizationCache{
		index: make(map[string]string, len(items)),
	}
	for i := range items {
		c.upsert(&items[i])
	}
	return c
}
