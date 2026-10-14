// Package sanitize makes free text safe to store and then print in a terminal.
package sanitize

import (
	"strings"
	"unicode"
)

// MaxRunes bounds a stored note. It is short on purpose: a note is a label, and
// an unbounded one is a way to fill someone's report with a paragraph.
const MaxRunes = 200

// Text drops anything that a terminal would consume rather than display.
//
// Control characters are the obvious case — an ESC sequence stored today is code
// executed in whoever's terminal tomorrow — but the bidirectional and zero-width
// overrides are equally dangerous and are *printable* by Unicode's own definition:
// U+202E can make `knell status` render a slug that is not the stored one. So this
// is a whitelist on printable characters with an explicit denylist on the
// invisible-direction controls, not a simple iscntrl filter.
func Text(s string) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	n := 0
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			r = ' '
		case r >= 0x202a && r <= 0x202e, // embedding, override, isolates
			r >= 0x2066 && r <= 0x2069, // directional isolates
			r == 0x200b, r == 0xfeff:   // zero-width space, BOM
			continue // dropped: invisible, and they change what a reader sees
		case !unicode.IsPrint(r):
			continue // dropped
		}
		b.WriteRune(r)
		if n++; n >= MaxRunes {
			break
		}
	}
	// Fields+join collapses the runs of spaces that \r\n and \t leave behind, and
	// trims: a note is a one-line label, and "one  two " is not information.
	return strings.Join(strings.Fields(b.String()), " ")
}
