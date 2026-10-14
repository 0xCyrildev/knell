package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTextDropsWhatATerminalWouldConsume(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "backup finished", "backup finished"},
		{"ansi colour", "\x1b[31mPWNED\x1b[0m", "[31mPWNED[0m"},
		{"bell", "beep\x07", "beep"},
		{"nul", "a\x00b", "ab"},
		{"newlines become spaces", "one\ntwo\r\nthree\tfour", "one two three four"},
		{"trailing whitespace trimmed", "  padded  ", "padded"},
	}
	for _, c := range cases {
		if got := Text(c.in); got != c.want {
			t.Errorf("%s: Text(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
	for _, in := range []string{"\x1b[31mPWNED\x1b[0m", "a\x00b", "x\x1b"} {
		if strings.ContainsRune(Text(in), 0x1b) || strings.ContainsRune(Text(in), 0) {
			t.Errorf("control byte survived %q", in)
		}
	}
}

// These are the interesting ones: the bidirectional and zero-width controls are
// printable by Unicode's definition, so an iscntrl filter leaves them in — and one
// of them can make `knell status` display a slug that is not the stored slug.
func TestTextDropsInvisibleDirectionControls(t *testing.T) {
	for _, r := range []rune{0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200b, 0xfeff} {
		in := "nightly" + string(r) + "-backup"
		got := Text(in)
		if strings.ContainsRune(got, r) {
			t.Errorf("U+%04X survived sanitising", r)
		}
		if got != "nightly-backup" {
			t.Errorf("Text(%q) = %q, want %q", in, got, "nightly-backup")
		}
	}
}

func TestTextIsBoundedInRunesNotBytes(t *testing.T) {
	long := strings.Repeat("é", MaxRunes+500)
	got := Text(long)
	if n := len([]rune(got)); n > MaxRunes {
		t.Errorf("got %d runes, want at most %d", n, MaxRunes)
	}
	if !utf8.ValidString(got) {
		t.Error("truncation produced invalid UTF-8")
	}
}

func TestTextHandlesInvalidUTF8(t *testing.T) {
	got := Text("bad\xff\xfebyte")
	if !utf8.ValidString(got) {
		t.Errorf("output is not valid UTF-8: %q", got)
	}
	if !strings.Contains(got, "bad") {
		t.Errorf("content lost: %q", got)
	}
}

func TestTextKeepsUsefulCharacters(t *testing.T) {
	in := "uploaded 12 GB — ok (nas0:~/backup) #42 30%"
	if got := Text(in); got != in {
		t.Errorf("Text(%q) = %q, want it unchanged", in, got)
	}
	for _, r := range "日本語" {
		if !strings.ContainsRune(Text("job:"+string(r)), r) {
			t.Errorf("non-latin text was dropped: %q", r)
		}
	}
}
