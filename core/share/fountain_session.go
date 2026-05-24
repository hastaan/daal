package share

import (
	"errors"
	"sync"

	"daal/bundle-go/fountain"
)

// FountainSession wraps an Encoder or Decoder with thread-safe access so
// the engine ABI can drive it from any thread.
type FountainSession struct {
	id       string
	mu       sync.Mutex
	enc      *fountain.Encoder
	dec      *fountain.Decoder
	complete []byte // populated once decode succeeds
}

// NewSenderSession builds a fountain encoder over the supplied payload.
// The session ID is opaque to the caller; persist it to drive successive
// NextFrame calls.
func NewSenderSession(id string, payload []byte, blockSize int, seed int64) *FountainSession {
	return &FountainSession{
		id:  id,
		enc: fountain.NewEncoder(payload, blockSize, seed),
	}
}

// NewReceiverSession is the receive-side counterpart.
func NewReceiverSession(id string) *FountainSession {
	return &FountainSession{
		id:  id,
		dec: fountain.NewDecoder(),
	}
}

// NextFrame returns one outgoing frame.
func (s *FountainSession) NextFrame() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enc == nil {
		return nil, errors.New("fountain: not a sender session")
	}
	return s.enc.NextFrame(), nil
}

// FeedFrame ingests a frame on the receive side. Returns (decoded payload,
// done, err). decoded is non-nil only when done==true.
func (s *FountainSession) FeedFrame(frame []byte) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dec == nil {
		return nil, false, errors.New("fountain: not a receiver session")
	}
	if s.complete != nil {
		return s.complete, true, nil
	}
	out, ok, err := s.dec.Add(frame)
	if err != nil {
		return nil, false, err
	}
	if ok {
		s.complete = out
	}
	return out, ok, nil
}

// Progress is recovered/total from the decoder side. For the encoder side,
// returns (sourceBlocks, sourceBlocks).
func (s *FountainSession) Progress() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dec != nil {
		return s.dec.Progress()
	}
	if s.enc != nil {
		return s.enc.SourceBlocks(), s.enc.SourceBlocks()
	}
	return 0, 0
}
