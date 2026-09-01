//go:build !windows

package credmanager

type unsupportedReader struct{}

func (unsupportedReader) Read(string) (Cred, bool, error) {
	return Cred{}, false, ErrUnsupported
}

func platformReader() Reader { return unsupportedReader{} }
