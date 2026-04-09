package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/scheme"

	mulicluster "go.miloapis.com/milo/pkg/multicluster-runtime"
)

var (
	// GroupVersion is group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "apiserver.config.miloapis.com", Version: "v1alpha1"}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&AuthProviderOpenFGA{})
}

type AuthProviderOpenFGA struct {
	metav1.TypeMeta `json:",inline"`

	Discovery DiscoveryConfig `json:"discovery"`
}

func (in *AuthProviderOpenFGA) DeepCopyInto(out *AuthProviderOpenFGA) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	out.Discovery = in.Discovery
}

func (in *AuthProviderOpenFGA) DeepCopy() *AuthProviderOpenFGA {
	if in == nil {
		return nil
	}
	out := new(AuthProviderOpenFGA)
	in.DeepCopyInto(out)
	return out
}

func (in *AuthProviderOpenFGA) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

type DiscoveryConfig struct {
	Mode                     mulicluster.Provider `json:"mode"`
	InternalServiceDiscovery bool                 `json:"internalServiceDiscovery"`
	DiscoveryKubeconfigPath  string               `json:"discoveryKubeconfigPath"`
	ProjectKubeconfigPath    string               `json:"projectKubeconfigPath"`
}

func (c *DiscoveryConfig) DiscoveryRestConfig() (*rest.Config, error) {
	if c.DiscoveryKubeconfigPath == "" {
		return ctrl.GetConfig()
	}
	return clientcmd.BuildConfigFromFlags("", c.DiscoveryKubeconfigPath)
}

func (c *DiscoveryConfig) ProjectRestConfig() (*rest.Config, error) {
	if c.ProjectKubeconfigPath == "" {
		return ctrl.GetConfig()
	}
	return clientcmd.BuildConfigFromFlags("", c.ProjectKubeconfigPath)
}
