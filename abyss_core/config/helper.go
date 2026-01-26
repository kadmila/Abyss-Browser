package config

func IF_DEBUG(f func()) {
	if DEBUG {
		f()
	}
}
