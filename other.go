//go:build !linux

package main

func landlockABI() int { return 0 }

func dieWithParent() error { return nil }
