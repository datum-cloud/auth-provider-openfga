package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/spf13/cobra"
	"go.miloapis.com/auth-provider-openfga/internal/webhook"
	iamv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/api/authentication/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"
)

func createWebhookCommand() *cobra.Command {
	var certDir, certFile, keyFile string
	var openfgaAPIURL string
	var openfgaStoreID string
	var openfgaScheme string
	var webhookPort int
	var metricsBindAddress string

	cmd := &cobra.Command{
		Use:   "authz-webhook",
		Short: "Start the OpenFGA authorization webhook server",
		Long:  "Start the authorization webhook server that validates SubjectAccessReview requests using OpenFGA.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runWebhookServer(
				certDir,
				certFile,
				keyFile,
				openfgaAPIURL,
				openfgaStoreID,
				openfgaScheme,
				webhookPort,
				metricsBindAddress,
			)
		},
	}

	cmd.Flags().StringVar(&certDir, "cert-dir", "/etc/certs",
		"Directory that contains the TLS certs to use for serving the webhook")
	cmd.Flags().StringVar(&certFile, "cert-file", "tls.crt", "Filename in the directory that contains the TLS cert")
	cmd.Flags().StringVar(&keyFile, "key-file", "tls.key", "Filename in the directory that contains the TLS private key")
	cmd.Flags().StringVar(&openfgaAPIURL, "openfga-api-url", "",
		"OpenFGA API URL (e.g. localhost:8080 or api.us1.fga.dev)")
	cmd.Flags().StringVar(&openfgaStoreID, "openfga-store-id", "", "OpenFGA Store ID")
	cmd.Flags().StringVar(&openfgaScheme, "openfga-scheme", "http", "OpenFGA Scheme (http or https)")
	cmd.Flags().IntVar(&webhookPort, "webhook-port", 9443, "Port for the webhook server")
	cmd.Flags().StringVar(&metricsBindAddress, "metrics-bind-address", ":8080", "Address for the metrics server")

	// Mark required flags
	if err := cmd.MarkFlagRequired("openfga-api-url"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-api-url as required: %v", err))
	}
	if err := cmd.MarkFlagRequired("openfga-store-id"); err != nil {
		panic(fmt.Sprintf("failed to mark openfga-store-id as required: %v", err))
	}

	return cmd
}

func runWebhookServer(
	certDir string,
	certFile string,
	keyFile string,
	openfgaAPIURL string,
	openfgaStoreID string,
	openfgaScheme string,
	webhookPort int,
	metricsBindAddress string,
) error {
	log.SetLogger(zap.New(zap.JSONEncoder()))
	entryLog := log.Log.WithName("webhook-server")

	// Create OpenFGA client
	var creds credentials.TransportCredentials
	if strings.ToLower(openfgaScheme) == "https" {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(openfgaAPIURL,
		grpc.WithTransportCredentials(creds),
	)
	if err != nil {
		return fmt.Errorf("unable to create gRPC connection to OpenFGA: %w", err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			entryLog.Error(closeErr, "failed to close gRPC connection")
		}
	}()

	fgaClient := openfgav1.NewOpenFGAServiceClient(conn)

	// Setup Kubernetes client config
	restConfig, err := config.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get rest config: %w", err)
	}

	runtimeScheme := runtime.NewScheme()
	if err := v1beta1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add v1beta1 to scheme: %w", err)
	}
	if err := resourcemanagerv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add resourcemanagerv1alpha1 to scheme: %w", err)
	}
	if err := iamv1alpha1.AddToScheme(runtimeScheme); err != nil {
		return fmt.Errorf("failed to add iamv1alpha1 to scheme: %w", err)
	}

	// Create Kubernetes client
	k8sClient, err := client.New(restConfig, client.Options{Scheme: runtimeScheme})
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	// Setup Manager
	entryLog.Info("setting up manager")
	mgr, err := manager.New(restConfig, manager.Options{
		Scheme: runtimeScheme,
		Metrics: server.Options{
			BindAddress: metricsBindAddress,
		},
		WebhookServer: ctrlwebhook.NewServer(ctrlwebhook.Options{
			CertDir:  certDir,
			CertName: certFile,
			KeyName:  keyFile,
			Port:     webhookPort,
		}),
	})
	if err != nil {
		return fmt.Errorf("failed to setup manager: %w", err)
	}

	// Setup webhooks
	entryLog.Info("setting up webhook server")
	hookServer := mgr.GetWebhookServer()

	entryLog.Info("registering webhooks to the webhook server")

	// Register the project control plane webhook
	hookServer.Register("/project/v1alpha/projects/{project}/webhook",
		webhook.NewAuthorizerWebhook(&webhook.ProjectControlPlaneAuthorizer{
			FGAClient:  fgaClient,
			FGAStoreID: openfgaStoreID,
			K8sClient:  k8sClient,
		}))

	// Register the core control plane webhook
	hookServer.Register("/core/v1alpha/webhook", webhook.NewAuthorizerWebhook(&webhook.CoreControlPlaneAuthorizer{
		FGAClient:  fgaClient,
		FGAStoreID: openfgaStoreID,
		K8sClient:  k8sClient,
	}))

	entryLog.Info("starting webhook server", "port", webhookPort, "metrics-port", metricsBindAddress)
	return mgr.Start(context.Background())
}
