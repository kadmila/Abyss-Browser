package watchdog

import (
	"encoding/hex"
	"fmt"
	"reflect"
)

func formatFlatLine(v interface{}) string {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	var out string
	for i := 0; i < val.NumField(); i++ {
		field := val.Type().Field(i)
		if !field.IsExported() {
			continue
		}

		fv := val.Field(i)
		if !isSimple(fv.Kind()) {
			continue // skip nested structs, slices except []byte, maps, etc.
		}
		out += " " + field.Name + "=" + formatValue(fv)
	}
	return out
}

func isSimple(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.String, reflect.Bool,
		reflect.Slice:
		return true
	default:
		return false
	}
}

func formatValue(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Slice: // we only keep []byte slices via isSimple()
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return hex.EncodeToString(v.Bytes()) // hex string
		}
		return "<slice>"
	case reflect.Bool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return fmt.Sprintf("%d", v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return fmt.Sprintf("%d", v.Uint())
	case reflect.Float32, reflect.Float64:
		return fmt.Sprintf("%g", v.Float())
	default:
		return "<unsupported>"
	}
}
