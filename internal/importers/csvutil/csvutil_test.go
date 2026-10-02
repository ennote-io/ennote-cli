package csvutil

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/ennote-io/ennote-cli/internal/importers"
)

func TestMatchesVault(t *testing.T) {
	row := &Row{cols: map[string]int{"folder": 0}, record: []string{`Dev\Cloud`}}
	if !row.MatchesVault("folder", "Dev") {
		t.Errorf("MatchesVault failed to match 'Dev' on folder column")
	}
	if row.MatchesVault("folder", "Prod") {
		t.Errorf("MatchesVault unexpectedly matched 'Prod' on folder column")
	}
}

func TestRowAccess(t *testing.T) {
	row := &Row{
		cols:   map[string]int{"name": 0, "url": 1, "notes": 2, "missing": 5},
		record: []string{"  AWS  ", "", "note"},
	}

	if got := row.Get("NAME"); got != "AWS" {
		t.Errorf("Get is not case-insensitive/trimming: %q", got)
	}
	if got := row.Get("absent"); got != "" {
		t.Errorf("Get(absent) = %q, want empty", got)
	}
	if got := row.Get("missing"); got != "" {
		t.Errorf("Get on out-of-range index = %q, want empty", got)
	}
	if !row.Has("notes") || row.Has("url") {
		t.Errorf("Has: notes=%v url=%v, want true/false", row.Has("notes"), row.Has("url"))
	}
}

func TestForEachRow(t *testing.T) {
	data := "Name,Login,Notes\n" +
		"AWS,admin,\"multi\nline\"\n" +
		"short\n" +
		"GitHub,octocat,ok\n"

	r := strings.NewReader(data)
	type seen struct {
		line  int
		name  string
		login string
		notes string
	}
	var rows []seen

	if err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		rows = append(rows, seen{row.Line, row.Get("name"), row.Get("login"), row.Get("notes")})
		return nil
	}); err != nil {
		t.Fatalf("ForEachRow failed: %v", err)
	}

	if len(rows) != 3 {
		t.Fatalf("expected 3 records, got %d (%+v)", len(rows), rows)
	}
	// Line numbers must point at the source line, and retained values must
	// survive the reader's record reuse.
	if rows[0] != (seen{2, "AWS", "admin", "multi\nline"}) {
		t.Errorf("unexpected first row: %+v", rows[0])
	}
	// Ragged record: absent columns read empty rather than panicking.
	if rows[1] != (seen{3, "short", "", ""}) {
		t.Errorf("unexpected ragged row: %+v", rows[1])
	}
	if rows[2] != (seen{4, "GitHub", "octocat", "ok"}) {
		t.Errorf("unexpected third row: %+v", rows[2])
	}
}

func TestForEachRow_HandlerErrorAborts(t *testing.T) {
	data := "name\na\nb\nc\n"
	r := strings.NewReader(data)
	sentinel := errors.New("stop")

	calls := 0
	err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		calls++
		return sentinel
	})

	if !errors.Is(err, sentinel) {
		t.Fatalf("expected handler error to propagate, got %v", err)
	}
	if calls != 1 {
		t.Errorf("expected scan to abort after 1 call, got %d", calls)
	}
}

func TestForEachRow_EmptyFile(t *testing.T) {
	r := strings.NewReader("")
	err := ForEachRow(r, 0, func(row *Row) error {
		t.Fatal("handler must not run for an empty file")
		return nil
	})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
}

func TestForEachRow_HeaderOnly(t *testing.T) {
	r := strings.NewReader("name,url\n")
	calls := 0
	if err := ForEachRow(r, int64(r.Len()), func(row *Row) error { calls++; return nil }); err != nil {
		t.Fatalf("header-only file should scan cleanly, got %v", err)
	}
	if calls != 0 {
		t.Errorf("expected 0 handler calls, got %d", calls)
	}
}

func TestRowIsEmpty(t *testing.T) {
	data := "name,login,password\n" +
		",,\n" +
		"  ,\t,  \n" +
		"Sparse,,\n"

	r := strings.NewReader(data)
	var empties []bool
	if err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		empties = append(empties, row.IsEmpty())
		return nil
	}); err != nil {
		t.Fatalf("ForEachRow failed: %v", err)
	}

	if want := []bool{true, true, false}; !slices.Equal(empties, want) {
		t.Errorf("IsEmpty per row = %v, want %v", empties, want)
	}
}

func TestForEachRow_BOMHeader(t *testing.T) {
	data := "\ufeffTitle,Username\nAWS,admin\n"
	r := strings.NewReader(data)

	var title, username string
	if err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		title, username = row.Get("title"), row.Get("username")
		return nil
	}); err != nil {
		t.Fatalf("ForEachRow failed: %v", err)
	}
	if title != "AWS" || username != "admin" {
		t.Errorf("BOM leaked into the first column: title=%q username=%q", title, username)
	}

	headers, err := ReadHeader(r, int64(r.Len()))
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(headers) != 2 || headers[0] != "title" || headers[1] != "username" {
		t.Errorf("ReadHeader = %q, want [title username]", headers)
	}
}

// Comma is the only delimiter. A semicolon- or tab-separated export is read as
// a single column, which no provider's MatchHeaders can claim, so it is
// rejected rather than half-parsed.
func TestForEachRow_CommaOnly(t *testing.T) {
	r := strings.NewReader("\ufeffName,Login,Notes\nAWS,admin,ok\n")
	rows := 0
	err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		rows++
		if row.Get("name") != "AWS" || row.Get("login") != "admin" || row.Get("notes") != "ok" {
			t.Errorf("row = %+v", row)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ForEachRow failed: %v", err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 record, got %d", rows)
	}

	semi := strings.NewReader("Name;Login;Notes\nAWS;admin;ok\n")
	headers, err := ReadHeader(semi, int64(semi.Len()))
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	if len(headers) != 1 || headers[0] != "name;login;notes" {
		t.Errorf("ReadHeader = %q, want the whole line as one column", headers)
	}
}

func TestForEachRow_CRLFWithEmbeddedNewline(t *testing.T) {
	data := "Name,Notes\r\nAWS,\"line1\nline2\"\r\nGitHub,ok\r\n"
	r := strings.NewReader(data)

	var got []string
	if err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		got = append(got, row.Get("name")+"|"+row.Get("notes"))
		return nil
	}); err != nil {
		t.Fatalf("ForEachRow failed: %v", err)
	}

	if len(got) != 2 || got[0] != "AWS|line1\nline2" || got[1] != "GitHub|ok" {
		t.Errorf("CRLF export parsed as %q", got)
	}
}

func TestForEachRow_WhitespaceOnly(t *testing.T) {
	r := strings.NewReader("   \n\n")
	err := ForEachRow(r, int64(r.Len()), func(row *Row) error {
		t.Fatal("handler must not run for a whitespace-only file")
		return nil
	})
	if !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("expected ErrEmptyExport, got %v", err)
	}
}

func TestReadHeader(t *testing.T) {
	r := strings.NewReader("\ufeff Title ,Login,Notes\nAWS,admin,ok\n")
	headers, err := ReadHeader(r, int64(r.Len()))
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}
	want := []string{"title", "login", "notes"}
	if len(headers) != len(want) {
		t.Fatalf("ReadHeader = %q, want %q", headers, want)
	}
	for i := range want {
		if headers[i] != want[i] {
			t.Fatalf("ReadHeader = %q, want %q", headers, want)
		}
	}

	empty := strings.NewReader("")
	if _, err := ReadHeader(empty, 0); !errors.Is(err, importers.ErrEmptyExport) {
		t.Fatalf("ReadHeader on empty input = %v, want ErrEmptyExport", err)
	}
}

func TestTruthy(t *testing.T) {
	for _, raw := range []string{"1", "true", "TRUE", "yes", "Yes", " 1 "} {
		if !Truthy(raw) {
			t.Errorf("Truthy(%q) = false, want true", raw)
		}
	}
	for _, raw := range []string{"0", "false", "no", "", "   ", "random"} {
		if Truthy(raw) {
			t.Errorf("Truthy(%q) = true, want false", raw)
		}
	}
}
