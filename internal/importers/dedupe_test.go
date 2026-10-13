package importers

import (
	"bytes"
	"testing"
)

func names(secrets []ImportedSecret) []string {
	out := make([]string, len(secrets))
	for i, s := range secrets {
		out[i] = s.Name
	}
	return out
}

func assertNames(t *testing.T, got []ImportedSecret, want []string) {
	t.Helper()
	gotNames := names(got)
	if len(gotNames) != len(want) {
		t.Fatalf("got %d secrets %v, want %d %v", len(gotNames), gotNames, len(want), want)
	}
	for i := range want {
		if gotNames[i] != want[i] {
			t.Errorf("name[%d] = %q, want %q (full: %v)", i, gotNames[i], want[i], gotNames)
		}
	}
}

func TestDeduplicateNames_SuffixesRepeats(t *testing.T) {
	got := DeduplicateNames([]ImportedSecret{
		{Name: "AWS"},
		{Name: "GitHub"},
		{Name: "AWS"},
		{Name: "AWS"},
	})
	assertNames(t, got, []string{"AWS", "GitHub", "AWS-1", "AWS-2"})
}

func TestDeduplicateNames_BlankNamesBecomeUntitled(t *testing.T) {
	got := DeduplicateNames([]ImportedSecret{
		{Name: ""},
		{Name: "Real"},
		{Name: ""},
	})
	assertNames(t, got, []string{"Untitled Secret", "Real", "Untitled Secret-1"})
}

func TestDeduplicateNames_AvoidsCollisionWithExistingSuffix(t *testing.T) {
	// The export already contains "AWS-1"; the naive counter would emit it twice.
	got := DeduplicateNames([]ImportedSecret{
		{Name: "AWS"},
		{Name: "AWS-1"},
		{Name: "AWS"},
	})
	assertNames(t, got, []string{"AWS", "AWS-1", "AWS-2"})

	seen := make(map[string]bool, len(got))
	for _, n := range names(got) {
		if seen[n] {
			t.Fatalf("duplicate name %q survived deduplication: %v", n, names(got))
		}
		seen[n] = true
	}
}

func TestDeduplicateNames_PreservesOtherFieldsAndOrder(t *testing.T) {
	payload := []byte(`{"login":"a","password":"b"}`)
	in := []ImportedSecret{
		{Name: "Dup", Type: TypeLoginPassword, URL: "https://a.example", Labels: []string{"dev"}, Notes: "first", Payload: payload},
		{Name: "Dup", Type: TypeTwoFactor, URL: "https://b.example", Labels: []string{"ops", "prod"}, Notes: "second"},
	}

	got := DeduplicateNames(in)
	assertNames(t, got, []string{"Dup", "Dup-1"})

	if got[0].Type != TypeLoginPassword || got[0].URL != "https://a.example" || got[0].Notes != "first" {
		t.Errorf("first secret mutated: %+v", got[0])
	}
	if !bytes.Equal(got[0].Payload, payload) {
		t.Errorf("payload mutated: %q", got[0].Payload)
	}
	if got[1].Type != TypeTwoFactor || len(got[1].Labels) != 2 || got[1].Labels[1] != "prod" {
		t.Errorf("second secret mutated: %+v", got[1])
	}
	if in[0].Name != "Dup" || in[1].Name != "Dup" {
		t.Errorf("input slice mutated: %v", names(in))
	}
}

func TestDeduplicateNames_EmptyInput(t *testing.T) {
	if got := DeduplicateNames(nil); len(got) != 0 {
		t.Errorf("expected no secrets, got %v", names(got))
	}
}
