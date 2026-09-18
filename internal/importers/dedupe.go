package importers

import "fmt"

const untitledSecretName = "Untitled Secret"

// DeduplicateNames gives every secret in a batch a unique name, appending -1,
// -2, ... to repeats. Blank names collapse onto "Untitled Secret" first.
// Candidates are probed against the names already emitted, so an export that
// already contains "AWS" and "AWS-1" cannot collide.
func DeduplicateNames(secrets []ImportedSecret) []ImportedSecret {
	if len(secrets) == 0 {
		return secrets
	}

	result := make([]ImportedSecret, len(secrets))
	counts := make(map[string]int, len(secrets))
	taken := make(map[string]struct{}, len(secrets))

	for i, s := range secrets {
		base := s.Name
		if base == "" {
			base = untitledSecretName
		}

		name := base
		for {
			if _, clash := taken[name]; !clash {
				break
			}
			counts[base]++
			name = fmt.Sprintf("%s-%d", base, counts[base])
		}

		taken[name] = struct{}{}
		s.Name = name
		result[i] = s
	}

	return result
}
