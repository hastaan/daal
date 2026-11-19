//go:build singbox

package engine

// ResetNetwork implements NetworkResetter (engine.go). It never holds
// s.mu across the reset: closing connections can wait on them.
func (s *singBox) ResetNetwork() {
	s.mu.Lock()
	inst := s.instance
	s.mu.Unlock()
	if inst == nil {
		return
	}
	defer func() { _ = recover() }() // an instance closing beside us
	inst.Router().ResetNetwork()
}
