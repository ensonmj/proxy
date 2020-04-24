package util

import (
	"io"
)

func ConnIO(remoteRW io.ReadWriteCloser, localW io.WriteCloser, localR io.Reader) error {
	writeCh := make(chan error)
	readCh := make(chan error)
	// write: local -> remote
	go func() {
		_, err := io.Copy(remoteRW, localR)
		remoteRW.Close()
		writeCh <- err
	}()
	// read: local <- remote
	go func() {
		_, err := io.Copy(localW, remoteRW)
		localW.Close()
		readCh <- err
	}()

	for {
		select {
		case <-writeCh:
			writeCh = nil
		case <-readCh:
			readCh = nil
		}
		if writeCh == nil && readCh == nil {
			return nil
		}
	}
}
