package authsome

import (
	"slices"
	"time"

	"github.com/xraph/authsome/id"
)

// stamp is a time as RFC 3339 in UTC, or nil when unset.
func stamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func stampPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return stamp(*t)
}

// day is the UTC date of t, or nil when unset. Fields that change on every
// request go as a date, so the population only changes once a day.
func day(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.DateOnly)
}

func dayPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return day(*t)
}

// optID is an ID's string, or nil for the zero ID.
func optID(v id.ID) any {
	if v.IsNil() {
		return nil
	}
	return v.String()
}

// optString is s, or nil when empty.
func optString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// sorted is a sorted copy of s, never nil.
func sorted(s []string) []string {
	out := append([]string{}, s...)
	slices.Sort(out)
	return out
}

func optBool(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
