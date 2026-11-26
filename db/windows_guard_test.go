package db

import (
	"regexp"
	"testing"
)

func TestWindowsGuardRules(t *testing.T) {
	var res []*regexp.Regexp
	for _, r := range windowsGuardRules {
		res = append(res, regexp.MustCompile(r.pattern))
	}
	match := func(s string) bool {
		for _, re := range res {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	// Commands as they appear in the raw JSON tool input.
	for _, s := range []string{
		`{"command":"rm -r -f /tmp/x"}`,
		`{"command":"Remove-Item C:\\x -Recurse -Force"}`,
		`{"command":"cmd /c rd C:\\x /s /q"}`,
		`{"command":"del /f /s /q C:\\x"}`,
		`{"command":"format d: /q"}`,
		`{"command":"Stop-Computer -Force"}`,
		`{"command":"schtasks /create /tn x /tr y"}`,
		`{"command":"Set-MpPreference -DisableRealtimeMonitoring $true"}`,
		`{"command":"vssadmin delete shadows /all"}`,
		`{"command":"reg add HKCU\\Software\\x"}`,
	} {
		if !match(s) {
			t.Errorf("not blocked: %s", s)
		}
	}
	for _, s := range []string{
		`{"command":"nmap -sV 10.0.0.5"}`,
		`{"command":"curl -s https://example.com/format?d=1"}`,
		`{"command":"Get-ChildItem -Recurse"}`,
		`{"command":"rm notes.txt"}`,
	} {
		if match(s) {
			t.Errorf("wrongly blocked: %s", s)
		}
	}
}
