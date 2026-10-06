package importers

import "testing"

func TestMatchesScope(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		filter    string
		want      bool
	}{
		{
			name:      "empty filter matches everything",
			candidate: "Dev/Cloud",
			filter:    "",
			want:      true,
		},
		{
			name:      "empty candidate matches nothing",
			candidate: "",
			filter:    "Dev",
			want:      false,
		},
		{
			name:      "exact match same separator",
			candidate: "Dev/Cloud",
			filter:    "Dev/Cloud",
			want:      true,
		},
		{
			name:      "exact match mixed backslash and slash",
			candidate: `Engineering\Backend`,
			filter:    "Engineering/Backend",
			want:      true,
		},
		{
			name:      "exact match case-insensitive",
			candidate: `ENGINEERING\BACKEND`,
			filter:    "engineering/backend",
			want:      true,
		},
		{
			name:      "parent folder matches subfolder",
			candidate: `Engineering\Backend\DB`,
			filter:    "Engineering/Backend",
			want:      true,
		},
		{
			name:      "parent folder matches top level",
			candidate: `Engineering\Backend`,
			filter:    "Engineering",
			want:      true,
		},
		{
			name:      "partial prefix without segment boundary does not match",
			candidate: "Development",
			filter:    "Dev",
			want:      false,
		},
		{
			name:      "filter with trailing slash",
			candidate: `Dev\Cloud`,
			filter:    "Dev/",
			want:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchesScope(tc.candidate, tc.filter); got != tc.want {
				t.Errorf("MatchesScope(%q, %q) = %v, want %v", tc.candidate, tc.filter, got, tc.want)
			}
		})
	}
}
