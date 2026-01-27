package functional

type Maybe[T any] struct {
	Value T
	ok    bool
}

func MakeMaybe[T any](value T) Maybe[T] {
	return Maybe[T]{Value: value, ok: true}
}

func (m Maybe[T]) Ok() bool {
	return m.ok
}

func (m Maybe[T]) Call(f func(T) (T, bool)) Maybe[T] {
	if !m.ok {
		return m
	}

	res, ok := f(m.Value)
	return Maybe[T]{res, ok}
}

func MaybeYield[T, Q any](input Maybe[T], f func(T) (Q, T, bool)) (Q, Maybe[T]) {
	var res Q
	if !input.ok {
		return res, input
	}

	res, next, ok := f(input.Value)
	return res, Maybe[T]{next, ok}
}

func MaybeJoin[T, Q, R any](lhs Maybe[T], rhs Maybe[Q], f func(T, Q) (R, bool)) Maybe[R] {
	var res R
	if !lhs.ok || !rhs.ok {
		return Maybe[R]{res, false}
	}

	res, ok := f(lhs.Value, rhs.Value)
	return Maybe[R]{res, ok}
}

/// error type

type MaybeErr[T any] struct {
	Value T
	err   error
}

func (m MaybeErr[T]) Err() error {
	return m.err
}

func (m MaybeErr[T]) Call(f func(T) (T, error)) MaybeErr[T] {
	if m.err != nil {
		return m
	}

	res, err := f(m.Value)
	return MaybeErr[T]{res, err}
}
