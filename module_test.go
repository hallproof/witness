package witness_test

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The root module must stay free of dependencies, so importing witness costs
// an app nothing it doesn't already have.
func TestModuleHasNoRequires(t *testing.T) {
	f, err := os.Open("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.HasPrefix(strings.TrimSpace(sc.Text()), "require") {
			t.Fatalf("go.mod requires a module: %q", sc.Text())
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
}

// Every package, tests included, imports only the standard library and
// witness itself.
func TestOnlyStdlib(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-test",
		"-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" && !strings.HasPrefix(line, "github.com/hallproof/witness") {
			t.Errorf("non-stdlib dependency: %s", line)
		}
	}
}
