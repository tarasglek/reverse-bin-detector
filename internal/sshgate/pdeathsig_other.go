//go:build !linux

package sshgate

func dieWithParent() error { return nil }
