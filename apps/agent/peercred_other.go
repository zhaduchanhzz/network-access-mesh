//go:build !linux

package main

import (
	"context"
	"errors"
	"io/fs"
	"net"
)

// The agent runs on Linux only (SO_PEERCRED); elsewhere it compiles but refuses every peer and every socket.
var errLinuxOnly = errors.New("the Host Agent runs on Linux only")

func peerCred(net.Conn) (uint32, uint32, int32, error) { return 0, 0, 0, errLinuxOnly }

func listenUnix(context.Context, string, int) (net.Listener, error) { return nil, errLinuxOnly }

func ownedBy(fs.FileInfo, int) bool { return false }
