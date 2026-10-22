package migrate

import (
	"fmt"
	"io/fs"
	"testing"
)

// mockSource is a test helper that implements Source.
type mockSource struct {
	name string
	deps []string
}

func (m *mockSource) Name() string           { return m.name }
func (m *mockSource) FS() fs.FS              { return nil }
func (m *mockSource) Dependencies() []string { return m.deps }

// Core must come first even when other sources have no dependencies, and the order of
// independent sources must be stable (their input order).
func TestTopoSort_CoreFirstAndDeterministic(t *testing.T) {
	sources := []Source{
		&mockSource{name: "oauth", deps: nil},
		&mockSource{name: "jwt", deps: nil},
		&mockSource{name: "core", deps: nil},
		&mockSource{name: "organization", deps: []string{"oauth"}},
		&mockSource{name: "apikey", deps: nil},
	}
	want := []string{"core", "oauth", "jwt", "apikey", "organization"}

	for range 50 {
		result, err := topoSort(sources)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := make([]string, len(result))
		for i, s := range result {
			got[i] = s.Name()
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestTopoSort_NoDependencies(t *testing.T) {
	sources := []Source{
		&mockSource{name: "core", deps: nil},
		&mockSource{name: "oauth", deps: nil},
		&mockSource{name: "jwt", deps: nil},
	}

	result, err := topoSort(sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 sources, got %d", len(result))
	}
}

func TestTopoSort_WithDependencies(t *testing.T) {
	sources := []Source{
		&mockSource{name: "core", deps: nil},
		&mockSource{name: "oauth", deps: []string{"core"}},
		&mockSource{name: "organization", deps: []string{"core", "oauth"}},
	}

	result, err := topoSort(sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("expected 3 sources, got %d", len(result))
	}

	// Verify ordering: core must come before oauth, oauth must come before organization
	indexOf := func(name string) int {
		for i, s := range result {
			if s.Name() == name {
				return i
			}
		}
		return -1
	}

	coreIdx := indexOf("core")
	oauthIdx := indexOf("oauth")
	orgIdx := indexOf("organization")

	if coreIdx > oauthIdx {
		t.Errorf("core should come before oauth, got core=%d, oauth=%d", coreIdx, oauthIdx)
	}
	if oauthIdx > orgIdx {
		t.Errorf("oauth should come before organization, got oauth=%d, org=%d", oauthIdx, orgIdx)
	}
}

func TestTopoSort_Cycle(t *testing.T) {
	sources := []Source{
		&mockSource{name: "a", deps: []string{"b"}},
		&mockSource{name: "b", deps: []string{"a"}},
	}

	_, err := topoSort(sources)
	if err == nil {
		t.Error("expected error for cyclic dependencies, got nil")
	}
}

func TestTopoSort_MissingDependency(t *testing.T) {
	sources := []Source{
		&mockSource{name: "oauth", deps: []string{"core"}},
	}

	_, err := topoSort(sources)
	if err == nil {
		t.Error("expected error for missing dependency, got nil")
	}
}

func TestTopoSort_EmptyInput(t *testing.T) {
	sources := []Source{}

	result, err := topoSort(sources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 0 {
		t.Errorf("expected 0 sources, got %d", len(result))
	}
}
