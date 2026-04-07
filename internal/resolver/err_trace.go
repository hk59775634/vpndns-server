package resolver

import (
	"errors"

	"github.com/vpndns/cdn/internal/models"
)

// ErrWithTrace wraps a resolver error together with the partial ResolveTrace built
// before the failure (client transport, ECS prelude, etc.) for query logs.
type ErrWithTrace struct {
	Trace *models.ResolveTrace
	Err   error
}

func (e *ErrWithTrace) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *ErrWithTrace) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// TraceFromError returns the trace carried by ErrWithTrace, or nil.
func TraceFromError(err error) *models.ResolveTrace {
	var et *ErrWithTrace
	if err != nil && errors.As(err, &et) && et != nil {
		return et.Trace
	}
	return nil
}

// FailureTraceForLog prefers the trace from a failed Resolve (ErrWithTrace); otherwise
// transport-only preflight (e.g. overload before prelude, or classic DNS).
func FailureTraceForLog(req *models.DNSRequest, err error) *models.ResolveTrace {
	if t := TraceFromError(err); t != nil {
		return t
	}
	return TransportTracePreflight(req)
}

func wrapResolveErr(tr *models.ResolveTrace, err error) error {
	if err == nil {
		return nil
	}
	if tr == nil {
		return err
	}
	tr.Steps = append(tr.Steps, "解析失败（未返回应答）："+err.Error())
	return &ErrWithTrace{Trace: tr, Err: err}
}
