// SPDX-FileCopyrightText: 2026 Petravault Contributors
// SPDX-License-Identifier: GPL-3.0-only

package backup

import (
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	pverrors "petravault/internal/errors"
	"petravault/internal/nofollow"
)

// Matcher reports whether a source-relative path is excluded (DESIGN.md
// §3.5). Excluded paths are not recorded in the snapshot.
type Matcher struct {
	patterns []compiledGlob
}

// compiledGlob is one exclude pattern compiled to a regular expression.
type compiledGlob struct {
	raw    string
	base   bool // match against the base name only (pattern holds no slash)
	dir    bool // trailing slash: directories only
	prefix string
}

// NewMatcher compiles glob patterns. Each pattern matches slash-separated
// paths relative to the source root: "*" spans one path element, "?"
// spans one character within an element, "**" spans elements, and a
// trailing slash restricts the pattern to directories. A pattern without a
// slash matches the base name at any depth. Malformed patterns fail closed.
func NewMatcher(patterns []string) (Matcher, error) {
	var m Matcher
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		c, err := compileGlob(p)
		if err != nil {
			return Matcher{}, err
		}
		m.patterns = append(m.patterns, c)
	}
	return m, nil
}

// LoadExcludeFile reads one glob per line, skipping blanks and lines
// starting with '#'. Files larger than 1 MiB are refused, matching the
// schedule job cap.
func LoadExcludeFile(file string) ([]string, error) {
	f, err := nofollow.Open(file)
	if err != nil {
		return nil, fmt.Errorf("read exclude file: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat exclude file: %w", err)
	}
	if fi.Size() > 1<<20 {
		return nil, fmt.Errorf("%w: exclude file %s too large", pverrors.ErrUsage, file)
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read exclude file: %w", err)
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("%w: exclude file %s too large", pverrors.ErrUsage, file)
	}
	var out []string
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

// Excluded reports whether rel (slash-separated, relative to the source
// root) is excluded. isDir tells whether rel names a directory.
func (m Matcher) Excluded(rel string, isDir bool) bool {
	base := path.Base(rel)
	for _, p := range m.patterns {
		if p.dir && !isDir {
			continue
		}
		target := rel
		if p.base {
			target = base
		}
		matched, err := path.Match(p.prefix, target)
		if err == nil && matched {
			return true
		}
		// path.Match cannot express "**" or character classes spanning
		// separators, so fall back to the compiled form when it holds one.
		if strings.Contains(p.raw, "**") && globStarMatch(p.prefix, target) {
			return true
		}
	}
	return false
}

// globStarMatch matches target against a pattern where "**" spans path
// separators. Single "*" and "?" stay within one element, and "[...]"
// classes match one non-separator character.
func globStarMatch(pattern, target string) bool {
	tokens := tokenizeGlob(pattern)
	chars := []rune(target)
	// dp[j] tracks whether the tokens consumed so far match target[:j].
	dp := make([]bool, len(chars)+1)
	dp[0] = true
	for _, tok := range tokens {
		next := make([]bool, len(chars)+1)
		switch tok.kind {
		case globLiteral:
			for j := range chars {
				if dp[j] && chars[j] == tok.char {
					next[j+1] = true
				}
			}
		case globAny:
			for j := range chars {
				if dp[j] && chars[j] != '/' {
					next[j+1] = true
				}
			}
		case globStar:
			for j := 0; j <= len(chars); j++ {
				if dp[j] {
					next[j] = true
					if j < len(chars) && chars[j] != '/' {
						dp[j+1] = true
					}
				}
			}
		case globDoubleStar:
			for j := 0; j <= len(chars); j++ {
				if dp[j] {
					next[j] = true
					if j < len(chars) {
						dp[j+1] = true
					}
				}
			}
		case globDoubleStarSlash:
			for j := 0; j <= len(chars); j++ {
				if dp[j] {
					next[j] = true
					for m := j; m < len(chars); m++ {
						if chars[m] == '/' {
							next[m+1] = true
						}
					}
				}
			}
		case globClass:
			for j := range chars {
				matched := slices.ContainsFunc(tok.class, func(bounds [2]rune) bool {
					return bounds[0] <= chars[j] && chars[j] <= bounds[1]
				})
				if dp[j] && chars[j] != '/' && matched != tok.negate {
					next[j+1] = true
				}
			}
		}
		dp = next
	}
	return dp[len(chars)]
}

// globToken is one element of a tokenized pattern.
type globToken struct {
	kind  globKind
	char  rune
	class [][2]rune
	// negate inverts membership without expanding Unicode ranges.
	negate bool
}

// globKind names the token types.
type globKind int

const (
	globLiteral globKind = iota
	globAny
	globStar
	globDoubleStar
	globDoubleStarSlash
	globClass
)

// tokenizeGlob splits a validated pattern into match tokens. The pattern
// passed bracket validation in compileGlob, so class parsing cannot fail.
func tokenizeGlob(pattern string) []globToken {
	var out []globToken
	chars := []rune(pattern)
	for i := 0; i < len(chars); {
		switch c := chars[i]; {
		// A "**/" also matches zero elements, so fold the slash into the
		// token: it matches empty or any prefix ending in '/'.
		case c == '*' && i+1 < len(chars) && chars[i+1] == '*':
			if i+2 < len(chars) && chars[i+2] == '/' {
				out = append(out, globToken{kind: globDoubleStarSlash})
				i += 3
			} else {
				out = append(out, globToken{kind: globDoubleStar})
				i += 2
			}
		case c == '*':
			out = append(out, globToken{kind: globStar})
			i++
		case c == '?':
			out = append(out, globToken{kind: globAny})
			i++
		case c == '[':
			tok := globToken{kind: globClass}
			j := i + 1
			if j < len(chars) && (chars[j] == '^' || chars[j] == '!') {
				tok.negate = true
				j++
			}
			if j < len(chars) && chars[j] == ']' {
				tok.class = append(tok.class, [2]rune{']', ']'})
				j++
			}
			for j < len(chars) && chars[j] != ']' {
				if j+2 < len(chars) && chars[j+1] == '-' && chars[j+2] != ']' {
					tok.class = append(tok.class, [2]rune{chars[j], chars[j+2]})
					j += 3
				} else {
					tok.class = append(tok.class, [2]rune{chars[j], chars[j]})
					j++
				}
			}
			out = append(out, tok)
			i = j + 1
		case c == '\\' && i+1 < len(chars):
			out = append(out, globToken{kind: globLiteral, char: chars[i+1]})
			i += 2
		default:
			out = append(out, globToken{kind: globLiteral, char: c})
			i++
		}
	}
	return out
}

// compileGlob validates one pattern and splits off its directory-only mark.
// Character classes are validated here; matching itself stays in path.Match
// (single-level) and globStarMatch (multi-level).
func compileGlob(pattern string) (compiledGlob, error) {
	raw := pattern
	dir := strings.HasSuffix(pattern, "/")
	pattern = strings.TrimSuffix(pattern, "/")
	if pattern == "" {
		return compiledGlob{}, fmt.Errorf("invalid exclude pattern %q: empty", raw)
	}
	depth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '[':
			depth++
			if i+1 < len(pattern) && (pattern[i+1] == '^' || pattern[i+1] == '!') {
				i++
			}
			if i+1 < len(pattern) && pattern[i+1] == ']' {
				i++
			}
		case ']':
			depth--
			if depth < 0 {
				return compiledGlob{}, fmt.Errorf("invalid exclude pattern %q: stray ']'", raw)
			}
		case '\\':
			i++
		}
	}
	if depth != 0 {
		return compiledGlob{}, fmt.Errorf("invalid exclude pattern %q: unclosed '['", raw)
	}
	if _, err := path.Match(pattern, "probe"); err != nil && !strings.Contains(pattern, "**") {
		return compiledGlob{}, fmt.Errorf("invalid exclude pattern %q: %w", raw, err)
	}
	return compiledGlob{raw: raw, base: !strings.Contains(pattern, "/"), dir: dir, prefix: pattern}, nil
}
