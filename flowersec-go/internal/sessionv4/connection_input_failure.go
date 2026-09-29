package sessionv4

import "io"

// connectionInputReader records only original shared/maintenance input calls.
// Authentication and dispatch are outside this boundary. The caller consumes
// the fact only if framing itself returns this failure, including ReadFull's
// standard EOF-to-UnexpectedEOF projection for an incomplete envelope.
type connectionInputReader struct {
	reader  io.Reader
	failure error
}

func (r *connectionInputReader) Read(dst []byte) (int, error) {
	r.failure = nil
	n, err := r.reader.Read(dst)
	if n >= 0 && n <= len(dst) && controllerNetworkRetry(err) {
		r.failure = err
	}
	return n, err
}

func (r *connectionInputReader) failed(err error) bool {
	return r.failure != nil && controllerNetworkRetry(err) &&
		(err == r.failure || r.failure == io.EOF && err == io.ErrUnexpectedEOF)
}
