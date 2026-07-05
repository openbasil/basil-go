package basil

import (
	"errors"
	"fmt"

	"github.com/openbasil/basil-go/internal/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatusError is the typed error returned when the broker rejects an RPC.
//
// It wraps the gRPC status and surfaces Basil's machine-readable detail: the
// canonical gRPC [codes.Code], the broker Reason token (for example
// "UNAUTHORIZED" or "INVALID_REQUEST"), and the Op that failed (for example
// "sign"). Reason and Op are empty when the broker attached no BrokerErrorInfo
// detail, for example on a transport-level failure.
//
// Match it with [errors.As]:
//
//	var se *basil.StatusError
//	if errors.As(err, &se) && se.Reason == "UNAUTHORIZED" {
//		// handle the denial
//	}
//
// StatusError also implements the GRPCStatus method, so the standard
// google.golang.org/grpc/status.Code and status.Convert helpers recover the
// canonical code from it.
type StatusError struct {
	// Code is the canonical gRPC status code.
	Code codes.Code
	// Reason is the broker's machine-readable reason token, or "" if absent.
	Reason string
	// Op is the broker operation that failed, or "" if absent.
	Op string
	// Message is the human-readable status message from the broker.
	Message string
}

// Error implements the error interface.
func (e *StatusError) Error() string {
	return fmt.Sprintf("basil: %s [%s/%s]: %s", e.Code, e.Reason, e.Op, e.Message)
}

// GRPCStatus returns the underlying gRPC status, letting StatusError
// interoperate with status.Code and status.Convert.
func (e *StatusError) GRPCStatus() *status.Status {
	return status.New(e.Code, e.Message)
}

// AsStatusError extracts a *StatusError from err, if one is present in its
// chain. It is a thin convenience wrapper over [errors.As].
func AsStatusError(err error) (*StatusError, bool) {
	var se *StatusError
	if errors.As(err, &se) {
		return se, true
	}
	return nil, false
}

// FromError normalizes err into a *StatusError, decoding the broker's
// BrokerErrorInfo detail (reason, op) when present. It returns nil for a nil
// error and leaves a non-gRPC error (for example a bare context error raised
// before the call reached the wire, or a client-side parse failure) unwrapped.
//
// It uses [status.FromError], which unwraps the error chain, so a gRPC status
// produced by the broker is recovered even when a higher-level library (for
// example the SPIFFE Workload API client) returns the RPC error verbatim. This
// makes FromError the single entry point for turning any Basil RPC error
// (broker data plane or SPIFFE Workload API) into a typed [StatusError].
func FromError(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	se := &StatusError{
		Code:    st.Code(),
		Message: st.Message(),
	}
	for _, d := range st.Details() {
		if info, ok := d.(*pb.BrokerErrorInfo); ok {
			se.Reason = info.GetReason()
			se.Op = info.GetOp()
			break
		}
	}
	return se
}

// statusError is the internal alias used by the broker sub-clients.
func statusError(err error) error { return FromError(err) }
