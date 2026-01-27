package functional

func Foreach[T any](s []T, f func(T)) {
	for _, e := range s {
		f(e)
	}
}
