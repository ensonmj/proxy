package util

import (
	"io"

	"github.com/pkg/errors"
)

func ConnIO(remoteRW io.ReadWriter, localW io.Writer, localR io.Reader) error {
	writeCh := make(chan error)
	readCh := make(chan error)
	// write: local -> remote
	go func() {
		_, err := io.Copy(remoteRW, localR)
		writeCh <- err
	}()
	// read: local <- remote
	go func() {
		_, err := io.Copy(localW, remoteRW)
		readCh <- err
	}()

	var writeErr, readErr error
	for {
		select {
		case writeErr = <-writeCh:
			writeCh = nil
		case readErr = <-readCh:
			readCh = nil
		}
		if writeCh == nil && readCh == nil {
			break
		}
	}
	if writeErr != nil || readCh != nil {
		return errors.Errorf("conn IO err [write:%s] [read:%s]",
			writeErr, readErr)
	}

	return nil
}
