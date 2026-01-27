package functional

func FuncReducePostfix[A1, A2, R any](f func(A1, A2) R, a2 A2) func(A1) R {
	return func(a1 A1) R {
		return f(a1, a2)
	}
}

func FuncReducePrefix[A1, A2, R any](a1 A1, f func(A1, A2) R) func(A2) R {
	return func(a2 A2) R {
		return f(a1, a2)
	}
}
