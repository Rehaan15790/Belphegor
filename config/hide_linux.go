package config

import "syscall"

// hideProcess marks the process non-dumpable, so other processes of the same user cannot read
// its /proc/<pid>/environ, memory or file descriptors.
func hideProcess() error {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
