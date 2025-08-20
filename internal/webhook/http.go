package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var authorizationScheme = runtime.NewScheme()
var authorizationCodecs = serializer.NewCodecFactory(authorizationScheme)

func init() {
	utilruntime.Must(authorizationv1.AddToScheme(authorizationScheme))
}

// Request defines the input for an authorization handler.
// It contains information to identify the object in
// question (group, version, kind, resource, subresource,
// name, namespace), as well as the operation in question
// (e.g. Get, Create, etc), and the object itself.
type Request struct {
	authorizationv1.SubjectAccessReview
}

// Response is the output of an authorization handler.
// It contains a response indicating if a given
// operation is allowed.
type Response struct {
	authorizationv1.SubjectAccessReview
}

// HandlerFunc implements Handler interface using a single function.
type HandlerFunc func(context.Context, Request) Response

// Handler can handle an SubjectAccessReview.
type Handler interface {
	// Handle yields a response to a SubjectAccessReview.
	//
	// The supplied context is extracted from the received http.Request, allowing wrapping
	// http.Handlers to inject values into and control cancelation of downstream request processing.
	Handle(context.Context, Request) Response
}

var _ Handler = HandlerFunc(nil)

// Handle process the SubjectAccessReview by invoking the underlying function.
func (f HandlerFunc) Handle(ctx context.Context, req Request) Response {
	return f(ctx, req)
}

var _ http.Handler = &Webhook{}

// ServeHTTP implements http.Handler.
func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	var err error

	ctx := r.Context()

	if wh.WithContextFunc != nil {
		ctx = wh.WithContextFunc(ctx, r)
	}

	var reviewResponse Response
	if r.Body == nil {
		err = errors.New("request body is empty")
		reviewResponse = Errored(err)
		wh.writeResponse(w, nil, reviewResponse)
		return
	}
	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			slog.ErrorContext(ctx, "failed to close request body", slog.String("error", closeErr.Error()))
		}
	}()

	if body, err = io.ReadAll(r.Body); err != nil {
		reviewResponse = Errored(err)
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	// verify the content type is accurate
	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		reviewResponse = Errored(fmt.Errorf("contentType=%s, expected application/json", contentType))
		wh.writeResponse(w, nil, reviewResponse)
		return
	}

	req := Request{}
	_, _, err = authorizationCodecs.UniversalDeserializer().Decode(body, nil, &req.SubjectAccessReview)
	if err != nil {
		reviewResponse = Errored(err)
		wh.writeResponse(w, &req, reviewResponse)
		return
	}

	reviewResponse = wh.Handle(ctx, req)
	if reviewResponse.Status.EvaluationError != "" {
		slog.ErrorContext(ctx, "evaluation error in webhook", slog.String("error", reviewResponse.Status.EvaluationError))
	}

	slog.InfoContext(
		ctx,
		"handled SubjectAccessReview webhook request",
		slog.Bool("allowed", reviewResponse.Status.Allowed),
		slog.Bool("denied", reviewResponse.Status.Denied),
		slog.String("user", req.Spec.User),
	)
	wh.writeResponse(w, &req, reviewResponse)
}

// writeResponse writes response resp to w. req is optional (can be nil) and adds
// context for the logger.
func (wh *Webhook) writeResponse(w io.Writer, req *Request, resp Response) {
	_ = req

	resp.SetGroupVersionKind(authorizationv1.SchemeGroupVersion.WithKind("SubjectAccessReview"))

	if err := json.NewEncoder(w).Encode(resp.SubjectAccessReview); err != nil {
		panic(err)
	}
}
