package resolver

import (
	"errors"
	"testing"

	"github.com/vpndns/cdn/internal/models"
)

func TestErrWithTraceUnwrap(t *testing.T) {
	inner := errors.New("inner")
	w := &ErrWithTrace{Trace: &models.ResolveTrace{Question: "A x."}, Err: inner}
	if !errors.Is(w, inner) {
		t.Fatal("expected errors.Is to unwrap")
	}
	if TraceFromError(w) == nil {
		t.Fatal("expected trace")
	}
	if TraceFromError(inner) != nil {
		t.Fatal("expected no trace for plain error")
	}
}

func TestWrapResolveErr(t *testing.T) {
	tr := &models.ResolveTrace{}
	err := wrapResolveErr(tr, errors.New("boom"))
	if TraceFromError(err) == nil {
		t.Fatal("expected trace")
	}
	if len(tr.Steps) == 0 || tr.Steps[len(tr.Steps)-1] != "解析失败（未返回应答）：boom" {
		t.Fatalf("steps: %#v", tr.Steps)
	}
}
