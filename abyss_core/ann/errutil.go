package ann

// Backlog push method

// backlogPushErr pushes an error to the backlog.
func (n *AbyssNode) backlogPushErr(err *HandshakeError) {
	n.backlog <- backLogEntry{
		peer: nil,
		err:  err,
	}
}
