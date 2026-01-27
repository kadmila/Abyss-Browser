package functional

func Accum_all[T any, Q any](s []T, init Q, f func(T, Q) Q) Q {
	result := init
	for _, e := range s {
		result = f(e, result)
	}
	return result
}
