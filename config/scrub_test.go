package config

import (
	"os"
	"strings"
	"testing"
)

func TestScrubEnvHidesSecretsFromChildren(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "k")
	t.Cleanup(func() { captured = map[string]string{} })
	if err := ScrubEnv(); err != nil {
		t.Fatal(err)
	}
	if v, ok := os.LookupEnv("ANTHROPIC_API_KEY"); ok {
		t.Fatalf("still in the environment: %q", v)
	}
	if got := Env("ANTHROPIC_API_KEY"); got != "k" {
		t.Fatalf("Env = %q, want k", got)
	}
}

func TestReadSecretsKeepsEqualsSigns(t *testing.T) {
	t.Cleanup(func() { captured = map[string]string{} })
	if err := readSecrets(strings.NewReader("BELPHEGOR_PG_DSN=postgres://u:p@h/d?sslmode=disable\nOPENAI_API_KEY=\n")); err != nil {
		t.Fatal(err)
	}
	if got := Env("BELPHEGOR_PG_DSN"); got != "postgres://u:p@h/d?sslmode=disable" {
		t.Fatalf("BELPHEGOR_PG_DSN = %q", got)
	}
	if got, ok := captured["OPENAI_API_KEY"]; !ok || got != "" {
		t.Fatalf("OPENAI_API_KEY = %q, %v", got, ok)
	}
}
