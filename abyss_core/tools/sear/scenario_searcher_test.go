package sear

import (
	"reflect"
	"testing"
)

type TestDecisionMachine struct {
	paths            map[int]int
	current_location int
	perm_log         []int
}

func (m *TestDecisionMachine) Initialize() {
	m.current_location = -1
}

func (m *TestDecisionMachine) GetInitPaths() int {
	return 3
}

func (m *TestDecisionMachine) Forward(path int) int {
	if m.current_location == -1 {
		m.current_location = path
	} else {
		m.current_location = m.current_location*10 + path
	}

	m.perm_log = append(m.perm_log, m.current_location)

	num_paths := m.paths[m.current_location]
	return num_paths
}

func MakeTestDecisionMachine() *TestDecisionMachine {
	result := new(TestDecisionMachine)
	result.paths = make(map[int]int)
	result.paths[0] = 0
	result.paths[1] = 2
	result.paths[10] = 1
	result.paths[100] = 2
	result.paths[1000] = 0
	result.paths[1001] = 0
	result.paths[11] = 0
	result.paths[2] = 2
	result.paths[20] = 0
	result.paths[21] = 3
	result.paths[210] = 0
	result.paths[211] = 0
	result.paths[212] = 0
	result.perm_log = make([]int, 0, 10)
	return result
}

func TestScenarioSearcher(t *testing.T) {
	machine := MakeTestDecisionMachine()
	searcher := MakeScenarioSearcher(machine)

	searcher.Run()
	if !reflect.DeepEqual(machine.perm_log, []int{0, 1, 10, 100, 1000, 1, 10, 100, 1001, 1, 11, 2, 20, 2, 21, 210, 2, 21, 211, 2, 21, 212}) {
		t.Fatalf("search failed")
	}
}
