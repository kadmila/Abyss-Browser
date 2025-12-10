package ann

type AbyssPeer struct {
	internal_id uint64
}

func NewAbyssPeer(connection *AuthenticatedConnection, internal_id uint64) *AbyssPeer {
	return &AbyssPeer{
		internal_id: internal_id,
	}
}

func (p *AbyssPeer) Close() error {
	return nil
}

func (p *AbyssPeer) Equal(subject *AbyssPeer) bool {
	return p.internal_id == subject.internal_id
}
