package config

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestScrubEnvHidesProcessFromChildren(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read every process")
	}
	if err := ScrubEnv(); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("cat", fmt.Sprintf("/proc/%d/environ", os.Getpid())).Run(); err == nil {
		t.Fatal("a child process could read the parent's environ")
	}
}
