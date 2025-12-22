package functional

func Filter[T any, Q any](s []T, f func(T) Q) []Q {
	result := make([]Q, len(s))
	for i, e := range s {
		result[i] = f(e)
	}
	return result
}

// Filter_MtS equlivalents to Filter, but takes and returns map.
func Filter_M[K comparable, T any, Q any](s map[K]T, f func(T) Q) map[K]Q {
	result := make(map[K]Q)
	for i, e := range s {
		result[i] = f(e)
	}
	return result
}

// Filter_MtS equlivalents to Filter, but takes map and returns slice.
func Filter_MtS[K comparable, T any, Q any](s map[K]T, f func(T) Q) []Q {
	result := make([]Q, 0, len(s))
	for _, e := range s {
		result = append(result, f(e))
	}
	return result
}

// Filter_ok takes an array and a function that returns (result, ok).
// The result values with ok == true is concatenated and returned.
func Filter_ok[T any, Q any](s []T, f func(T) (Q, bool)) []Q {
	result := make([]Q, 0, len(s))
	for _, e := range s {
		v, ok := f(e)
		if ok {
			result = append(result, v)
		}
	}
	return result
}

// Filter_MtS_ok equlivalents to Filter_ok, but takes map and returns slice.
func Filter_MtS_ok[K comparable, T any, Q any](s map[K]T, f func(T) (Q, bool)) []Q {
	result := make([]Q, 0, len(s))
	for _, e := range s {
		v, ok := f(e)
		if ok {
			result = append(result, v)
		}
	}
	return result
}

func Filter_strict_ok[T any, Q any](s []T, f func(T) (Q, bool)) ([]Q, bool) {
	result := make([]Q, len(s))
	for i, e := range s {
		v, ok := f(e)
		if !ok {
			return nil, false
		}
		result[i] = v
	}
	return result, true
}

// Filter_until_err takes an array and a function that returns a result and an error,
// tries to filter all entries, but stops if one call returns error.
// Returns result, remnant (nil if success), error
// When fails, the first entry of the remnant is the one which caused the error.
func Filter_until_err[T any, Q any](s []T, f func(T) (Q, error)) ([]Q, []T, error) {
	result := make([]Q, 0, len(s))
	for i, e := range s {
		v, err := f(e)
		if err != nil {
			return result, s[i:], err
		}
		result = append(result, v)
	}
	return result, nil, nil
}
