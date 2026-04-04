package resolver

import "errors"

// ErrOverload signals global QPS or overload policy rejected the resolve before upstream work.
var ErrOverload = errors.New("overload")
