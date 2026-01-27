package dacp

import (
	"reflect"
	"strconv"
	"testing"
)

func TestActionPool(t *testing.T) {
	expected_array := []int{4, 5, 1, 2, 3}
	result_array := make([]int, 0, 10)

	action_pool := MakeDiscreteActionPool()
	r1 := action_pool.AddAction(NewDiscreteAction(func() { result_array = append(result_array, 1) }, 0))
	r2 := action_pool.AddAction(NewDiscreteAction(func() { result_array = append(result_array, 2) }, r1))
	action_pool.AddAction(NewDiscreteAction(func() { result_array = append(result_array, 3) }, r2))
	r4 := action_pool.AddAction(NewDiscreteAction(func() { result_array = append(result_array, 4) }, 0))
	action_pool.AddAction(NewDiscreteAction(func() { result_array = append(result_array, 5) }, r4))

	for len(action_pool.actions_ready) != 0 {
		action := action_pool.PopAction(len(action_pool.actions_ready) - 1)
		action.action()
	}

	if !reflect.DeepEqual(expected_array, result_array) {
		result_string := ""
		for _, r := range result_array {
			result_string += strconv.Itoa(r) + " "
		}
		t.Fatalf("%s", "result not matching: [ "+result_string+"]")
	}
}
