package endpoint

import "github.com/floegence/flowersec/flowersec-go/fserrors"

func wrapErr(path fserrors.Path, stage fserrors.Stage, code fserrors.Code, err error) error {
	return fserrors.Wrap(path, stage, code, err)
}
