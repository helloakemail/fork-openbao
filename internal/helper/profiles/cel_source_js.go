//go:build js

package profiles

import (
	"context"
	"errors"
)

// The js/wasm build excludes the CEL engine (cel-go, antlr) to keep the
// binary small. The "cel" source stays registered so profiles that use it
// fail validation with a clear error rather than an unknown-source error.

var errCELUnsupported = errors.New("CEL is not supported on this build")

func CELSourceBuilder(_ *ProfileEngine, _ map[string]any) Source {
	return &CELSource{}
}

var _ SourceBuilder = CELSourceBuilder

func WithCELSource() func(*ProfileEngine) {
	return func(p *ProfileEngine) {
		p.sourceBuilders["cel"] = CELSourceBuilder
	}
}

type CELSource struct{}

var _ Source = &CELSource{}

func (s *CELSource) Validate() ([]string, []string, error) {
	return nil, nil, errCELUnsupported
}

func (s *CELSource) Evaluate(context.Context, *EvaluationHistory) (any, error) {
	return nil, errCELUnsupported
}

func (s *CELSource) Close(context.Context) error {
	return nil
}
