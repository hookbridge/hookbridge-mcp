package hbmcp

import (
	"fmt"
	"regexp"
	"time"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const (
	defaultLimit  = 50
	maxLimit      = 100
	maxCursorLen  = 512
	maxFutureSkew = 5 * time.Minute
)

// resolveProject checks project_id against the auth mode and returns the
// project to send in X-Hookbridge-Project, which is empty for API keys.
func resolveProject(o Options, given string) (string, error) {
	if o.Auth == AuthAPIKey {
		switch {
		case given == "":
			return "", nil
		case o.APIKeyProjectID == "":
			return "", userErrorf("This connection uses one API key tied to one project. Leave project_id empty.")
		case given != o.APIKeyProjectID:
			return "", userErrorf("This connection's API key belongs to project %s. Leave project_id empty or use that ID.", o.APIKeyProjectID)
		}
		return "", nil
	}
	if given == "" {
		return "", userErrorf("project_id is required. Call list_projects to find it.")
	}
	if !uuidRe.MatchString(given) {
		return "", userErrorf("project_id must be a valid UUID (lowercase, with dashes). Call list_projects to find it.")
	}
	return given, nil
}

type paging struct {
	Cursor string
	Limit  int
}

func parsePaging(cursor string, limit *int) (paging, error) {
	p := paging{Cursor: cursor, Limit: defaultLimit}
	if limit != nil {
		p.Limit = *limit
		if p.Limit < 1 || p.Limit > maxLimit {
			return paging{}, userErrorf("limit must be between 1 and %d", maxLimit)
		}
	}
	if len(cursor) > maxCursorLen {
		return paging{}, userErrorf("cursor is too long; pass back the cursor value exactly as returned")
	}
	for i := 0; i < len(cursor); i++ {
		if cursor[i] < 0x21 || cursor[i] > 0x7e {
			return paging{}, userErrorf("cursor has invalid characters; pass back the cursor value exactly as returned")
		}
	}
	return p, nil
}

// parseTimeRange parses optional RFC 3339 start_time and end_time values.
func parseTimeRange(start, end string, now time.Time) (*time.Time, *time.Time, error) {
	parse := func(name, v string) (*time.Time, error) {
		if v == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, userErrorf("%s must be an RFC 3339 timestamp such as 2026-01-31T15:04:05Z", name)
		}
		if t.After(now.Add(maxFutureSkew)) {
			return nil, userErrorf("%s is in the future", name)
		}
		return &t, nil
	}
	s, err := parse("start_time", start)
	if err != nil {
		return nil, nil, err
	}
	e, err := parse("end_time", end)
	if err != nil {
		return nil, nil, err
	}
	if s != nil && e != nil && !s.Before(*e) {
		return nil, nil, userErrorf("start_time must be before end_time")
	}
	return s, e, nil
}

type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func userErrorf(format string, args ...any) error {
	return &userError{msg: fmt.Sprintf(format, args...)}
}
