//go:build !linux && !darwin

package main

import "os/exec"

func configureCollectionCommand(_ *exec.Cmd) {}
