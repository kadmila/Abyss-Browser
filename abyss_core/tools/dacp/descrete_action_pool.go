package dacp

type DiscreteAction struct {
	id           int
	action       func()
	precursor_id int
}

var action_counter int

func NewDiscreteAction(action func(), precursor_id int) *DiscreteAction {
	result := new(DiscreteAction)
	action_counter++
	result.id = action_counter
	result.action = action
	result.precursor_id = precursor_id
	return result
}

func (a *DiscreteAction) Exec() {
	a.action()
}

type DiscreteActionPool struct {
	actions_ready   []*DiscreteAction
	actions_pending []*DiscreteAction
}

func MakeDiscreteActionPool() DiscreteActionPool {
	return DiscreteActionPool{actions_ready: make([]*DiscreteAction, 0), actions_pending: make([]*DiscreteAction, 0)}
}
func (p *DiscreteActionPool) PopAction(index int) *DiscreteAction {
	result := p.actions_ready[index]
	p.actions_ready = append(p.actions_ready[:index], p.actions_ready[index+1:]...)

	stil_pending_actions := make([]*DiscreteAction, 0)
	for _, pending_action := range p.actions_pending {
		if pending_action.precursor_id == result.id {
			p.actions_ready = append(p.actions_ready, pending_action)
		} else {
			stil_pending_actions = append(stil_pending_actions, pending_action)
		}
	}
	p.actions_pending = stil_pending_actions

	return result
}
func (p *DiscreteActionPool) AddAction(action *DiscreteAction) int {
	for _, ra := range p.actions_ready {
		if ra.id == action.precursor_id {
			p.actions_pending = append(p.actions_pending, action)
			return action.id
		}
	}
	for _, pa := range p.actions_pending {
		if pa.id == action.precursor_id {
			p.actions_pending = append(p.actions_pending, action)
			return action.id
		}
	}

	p.actions_ready = append(p.actions_ready, action)
	return action.id
}

func (p *DiscreteActionPool) GetActionN() int {
	return len(p.actions_ready)
}
