package migrate

import "fmt"

// topoSort performs a topological sort on migration sources based on their dependencies.
// Core is always first in the output. Returns ErrDependencyCycle if a cycle is detected,
// or ErrMissingDependency if a source depends on something not in the input.
func topoSort(sources []Source) ([]Source, error) {
	// Build name -> source map
	byName := make(map[string]Source, len(sources))
	for _, s := range sources {
		byName[s.Name()] = s
	}

	// Check all dependencies exist
	for _, s := range sources {
		for _, dep := range s.Dependencies() {
			if _, ok := byName[dep]; !ok {
				return nil, &DependencyError{
					Source:     s.Name(),
					Dependency: dep,
					Err:        ErrMissingDependency,
				}
			}
		}
	}

	// Kahn's algorithm for topological sort
	// Calculate in-degree for each source
	inDegree := make(map[string]int, len(sources))
	for _, s := range sources {
		if _, exists := inDegree[s.Name()]; !exists {
			inDegree[s.Name()] = 0
		}
		for _, dep := range s.Dependencies() {
			inDegree[s.Name()]++
			// Ensure dependency exists in map
			if _, exists := inDegree[dep]; !exists {
				inDegree[dep] = 0
			}
		}
	}

	// Find all sources with no dependencies (in-degree 0)
	var queue []string
	for name, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, name)
		}
	}

	// Process queue
	var result []Source
	for len(queue) > 0 {
		// Pop from queue
		name := queue[0]
		queue = queue[1:]

		// Add to result if it's one of our sources
		if s, ok := byName[name]; ok {
			result = append(result, s)
		}

		// For each source that depends on this one, decrease its in-degree
		for _, s := range sources {
			for _, dep := range s.Dependencies() {
				if dep == name {
					inDegree[s.Name()]--
					if inDegree[s.Name()] == 0 {
						queue = append(queue, s.Name())
					}
				}
			}
		}
	}

	// If we didn't process all sources, there's a cycle
	if len(result) != len(sources) {
		return nil, fmt.Errorf("%w: not all sources could be sorted", ErrDependencyCycle)
	}

	return result, nil
}
