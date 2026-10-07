package onepassword

import (
	"bytes"
	"testing"
)

func TestPUXImporter_MatchFile(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		file string
		want bool
	}{
		{"extension alone", []byte("not even json"), "export.1pux", true},
		{"raw export.data json", []byte(`{"attrs":{},"accounts":[]}`), "export.json", true},
		{"json without accounts key", []byte(`{"items":[{"accounts":1}]}`), "export.json", false},
		{"csv export", []byte("Title,Username,Password\nAWS,root,pw\n"), "export.csv", false},
		{"empty file", nil, "export.bin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPUXImporter().MatchFile(bytes.NewReader(tt.data), int64(len(tt.data)), tt.file)
			if got != tt.want {
				t.Errorf("MatchFile(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func TestPUXImporter_MatchFileZipArchive(t *testing.T) {
	archive := createSynthetic1PUXZip(t)

	if !NewPUXImporter().MatchFile(bytes.NewReader(archive), int64(len(archive)), "export.zip") {
		t.Error("MatchFile must recognize a 1PUX zip by its members, not its extension")
	}
}
