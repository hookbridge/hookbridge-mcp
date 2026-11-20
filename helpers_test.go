package hbmcp

import (
	"strings"
	"testing"
	"time"
)

const (
	projA = "11111111-2222-4333-8444-555555555555"
	projB = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func TestResolveProject(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		given   string
		want    string
		wantErr string
	}{
		{"oauth ok", Options{Auth: AuthOAuth}, projA, projA, ""},
		{"oauth missing", Options{Auth: AuthOAuth}, "", "", "project_id is required"},
		{"oauth bad format", Options{Auth: AuthOAuth}, "not-a-uuid", "", "valid UUID"},
		{"oauth uppercase rejected", Options{Auth: AuthOAuth}, strings.ToUpper(projB), "", "valid UUID"},
		{"oauth header injection", Options{Auth: AuthOAuth}, projA + "\r\nX: y", "", "valid UUID"},
		{"key omitted", Options{Auth: AuthAPIKey}, "", "", ""},
		{"key omitted known project", Options{Auth: AuthAPIKey, APIKeyProjectID: projA}, "", "", ""},
		{"key match", Options{Auth: AuthAPIKey, APIKeyProjectID: projA}, projA, "", ""},
		{"key mismatch", Options{Auth: AuthAPIKey, APIKeyProjectID: projA}, projB, "", "belongs to project " + projA},
		{"key unknown project given", Options{Auth: AuthAPIKey}, projA, "", "project_id empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveProject(tt.opts, tt.given)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePaging(t *testing.T) {
	ptr := func(i int) *int { return &i }
	tests := []struct {
		name       string
		cursor     string
		limit      *int
		wantLimit  int
		wantErrSub string
	}{
		{"defaults", "", nil, 50, ""},
		{"explicit", "abc_-.=", ptr(100), 100, ""},
		{"one", "", ptr(1), 1, ""},
		{"zero", "", ptr(0), 0, "limit must be between 1 and 100"},
		{"negative", "", ptr(-3), 0, "limit must be between 1 and 100"},
		{"too big", "", ptr(101), 0, "limit must be between 1 and 100"},
		{"cursor too long", strings.Repeat("a", 513), nil, 0, "cursor"},
		{"cursor control", "ab\ncd", nil, 0, "cursor"},
		{"cursor non-ascii", "abé", nil, 0, "cursor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parsePaging(tt.cursor, tt.limit)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Limit != tt.wantLimit || p.Cursor != tt.cursor {
				t.Errorf("got %+v", p)
			}
		})
	}
}

func TestParseTimeRange(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name       string
		start, end string
		wantStart  bool
		wantEnd    bool
		wantErrSub string
	}{
		{"none", "", "", false, false, ""},
		{"both", "2026-11-19T00:00:00Z", "2026-11-20T00:00:00Z", true, true, ""},
		{"offset", "2026-11-19T00:00:00+02:00", "", true, false, ""},
		{"bad start", "yesterday", "", false, false, "start_time"},
		{"bad end", "", "2026-11-20", false, false, "end_time"},
		{"start after end", "2026-11-20T00:00:00Z", "2026-11-19T00:00:00Z", false, false, "before end_time"},
		{"equal", "2026-11-20T00:00:00Z", "2026-11-20T00:00:00Z", false, false, "before end_time"},
		{"future start", "2027-11-20T00:00:00Z", "", false, false, "future"},
		{"future end", "", "2030-01-01T00:00:00Z", false, false, "future"},
		{"small skew ok", "", "2026-11-20T12:03:00Z", false, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, e, err := parseTimeRange(tt.start, tt.end, now)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (s != nil) != tt.wantStart || (e != nil) != tt.wantEnd {
				t.Errorf("start=%v end=%v", s, e)
			}
		})
	}
}
