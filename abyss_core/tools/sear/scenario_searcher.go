package sear

type scenarioNode struct {
	parent      *scenarioNode
	children    []*scenarioNode
	is_final    bool //is children determined
	is_searched bool //is child paths all searched
}

func newScenarioNode(parent *scenarioNode) *scenarioNode {
	result := new(scenarioNode)
	result.parent = parent
	result.children = make([]*scenarioNode, 0)
	result.is_final = false
	result.is_searched = false
	return result
}

func (s *scenarioNode) openScenarioPaths(num_paths int) {
	if s.is_final {
		if len(s.children) != num_paths {
			panic("scenario path overwritten")
		}
		return
	}

	for i := 0; i < num_paths; i++ {
		s.children = append(s.children, newScenarioNode(s))
	}

	s.is_final = true
}

type scenarioMap struct {
	root         *scenarioNode
	current_node *scenarioNode
}

func newScenarioMap() *scenarioMap {
	result := new(scenarioMap)
	result.root = newScenarioNode(nil)
	result.current_node = result.root
	return result
}

func _mark_searched_parent_nodes(current_node *scenarioNode) {
	if current_node.parent == nil { // current_node is root node
		return
	}

	if current_node.parent.children[len(current_node.parent.children)-1] == current_node {
		current_node.parent.is_searched = true
		_mark_searched_parent_nodes(current_node.parent)
	}
}

func (s *scenarioMap) tryGetNextSearchBranch() (int, bool, bool) { // branch, is_end, ok
	if !s.current_node.is_final {
		panic("entered unfinialized path")
	}

	for i, child := range s.current_node.children {
		if child.is_searched {
			continue
		}

		if len(child.children) == 0 && child.is_final { // check if child is a leaf node.
			child.is_searched = true
			_mark_searched_parent_nodes(child)
			s.current_node = s.root
			return i, true, true
		} else {
			s.current_node = child // child may not be finialized.
			return i, false, true
		}
	}

	if len(s.current_node.children) == 0 {
		s.current_node.is_searched = true
		_mark_searched_parent_nodes(s.current_node)
		s.current_node = s.root
		return -1, true, true
	}

	return -1, false, false
}

type IDecisionMachine interface {
	Initialize()
	GetInitPaths() int
	Forward(path int) int //return number of next branches
}

type ScenarioSearcher struct {
	scenario_map *scenarioMap
	machine      IDecisionMachine
}

func MakeScenarioSearcher(machine IDecisionMachine) ScenarioSearcher {
	result := ScenarioSearcher{}
	result.scenario_map = newScenarioMap()
	result.machine = machine
	return result
}

func (s *ScenarioSearcher) Run() {
	s.machine.Initialize()
	s.scenario_map.root.openScenarioPaths(s.machine.GetInitPaths())

	running := true
	for {
		target_branch := s.scenario_map.root

		for {
			branch, _, ok := s.scenario_map.tryGetNextSearchBranch()
			if !ok {
				running = false
				break
			}

			if branch == -1 {
				break
			}

			target_branch = target_branch.children[branch]
			next_paths := s.machine.Forward(branch)
			target_branch.openScenarioPaths(next_paths)
		}

		if running {
			s.machine.Initialize()
		} else {
			break
		}
	}
}
