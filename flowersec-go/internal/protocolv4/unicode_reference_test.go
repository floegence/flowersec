package protocolv4

// Test-only UAX #15 reference over the pinned repository tables. This does not
// use Go's current Unicode normalization version or qualify a runtime adapter.
import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type nfcReference struct {
	classes       map[rune]int
	decomposition map[rune][]rune
	composition   map[[2]rune]rune
	ranges        [][2]rune
	sources       map[string]struct{ SHA256 string }
}

func newNFCReference(t testing.TB, relative, hash string) *nfcReference {
	t.Helper()
	if relative != "testdata/unicode15_1/normalization_generated.json" {
		t.Fatal("unexpected normalization data path")
	}
	raw, err := os.ReadFile(filepath.Join("../../..", relative))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != hash {
		t.Fatal("normalization data hash drift")
	}
	var data struct {
		Version        string `json:"unicode_version"`
		CCC            [][2]int
		Decompositions []json.RawMessage
		Compositions   [][3]rune
		Assigned       [][2]rune
		Sources        map[string]struct{ SHA256 string }
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if data.Version != "15.1.0" {
		t.Fatal("Unicode version drift")
	}
	r := &nfcReference{classes: map[rune]int{}, decomposition: map[rune][]rune{}, composition: map[[2]rune]rune{}, ranges: data.Assigned, sources: data.Sources}
	for _, pair := range data.CCC {
		r.classes[rune(pair[0])] = pair[1]
	}
	for _, rawPair := range data.Decompositions {
		var pair [2]json.RawMessage
		var cp rune
		var parts []rune
		if err := json.Unmarshal(rawPair, &pair); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(pair[0], &cp); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(pair[1], &parts); err != nil {
			t.Fatal(err)
		}
		r.decomposition[cp] = parts
	}
	for _, triple := range data.Compositions {
		r.composition[[2]rune{triple[0], triple[1]}] = triple[2]
	}
	return r
}

func (r *nfcReference) assigned(cp rune) bool {
	if cp < 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) {
		return false
	}
	i := sort.Search(len(r.ranges), func(i int) bool { return r.ranges[i][1] >= cp })
	return i < len(r.ranges) && r.ranges[i][0] <= cp
}

func (r *nfcReference) decompose(out []rune, cp rune) []rune {
	// UAX #15 algorithmic Hangul decomposition, independent of table entries.
	if cp >= 0xac00 && cp < 0xac00+11172 {
		n := cp - 0xac00
		out = append(out, 0x1100+n/588, 0x1161+(n%588)/28)
		if n%28 != 0 {
			out = append(out, 0x11a7+n%28)
		}
		return out
	}
	if parts, ok := r.decomposition[cp]; ok {
		for _, part := range parts {
			out = r.decompose(out, part)
		}
		return out
	}
	return append(out, cp)
}

func (r *nfcReference) compose(a, b rune) (rune, bool) {
	if a >= 0x1100 && a < 0x1100+19 && b >= 0x1161 && b < 0x1161+21 {
		return 0xac00 + ((a-0x1100)*21+b-0x1161)*28, true
	}
	if a >= 0xac00 && a < 0xac00+11172 && (a-0xac00)%28 == 0 && b > 0x11a7 && b < 0x11a7+28 {
		return a + b - 0x11a7, true
	}
	value, ok := r.composition[[2]rune{a, b}]
	return value, ok
}

func (r *nfcReference) normalize(input string) string {
	decomposed := make([]rune, 0, len(input))
	for _, cp := range input {
		decomposed = r.decompose(decomposed, cp)
	}
	// Stable sorting preserves equal-class blocking and avoids quadratic
	// insertion on a long reversed combining run. Starters never move.
	for start := 0; start < len(decomposed); {
		if r.classes[decomposed[start]] == 0 {
			start++
			continue
		}
		end := start + 1
		for end < len(decomposed) && r.classes[decomposed[end]] != 0 {
			end++
		}
		marks := decomposed[start:end]
		sort.SliceStable(marks, func(i, j int) bool { return r.classes[marks[i]] < r.classes[marks[j]] })
		start = end
	}
	output := make([]rune, 0, len(decomposed))
	starter, lastClass := -1, 0
	for _, cp := range decomposed {
		class := r.classes[cp]
		if starter >= 0 && (lastClass == 0 || lastClass < class) {
			if composite, ok := r.compose(output[starter], cp); ok {
				output[starter] = composite
				continue
			}
		}
		if class == 0 {
			starter = len(output)
		}
		output = append(output, cp)
		lastClass = class
	}
	return string(output)
}

// v4.cbor.unicode
func TestCBORUnicodeReferenceConformance(t *testing.T) {
	r := newCBORReference(t).unicode
	raw, err := os.ReadFile("../../../testdata/unicode15_1/NormalizationTest.txt")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != r.sources["NormalizationTest.txt"].SHA256 {
		t.Fatal("normalization corpus hash drift")
	}
	covered := map[rune]bool{}
	part, count := "", 0
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "@Part") {
			part = strings.Fields(line)[0]
		}
		source := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if source == "" || strings.HasPrefix(source, "@") {
			continue
		}
		columns := strings.Split(source, ";")
		var text [5]string
		for i := range text {
			var scalars []rune
			for _, value := range strings.Fields(columns[i]) {
				cp, err := strconv.ParseInt(value, 16, 32)
				if err != nil {
					t.Fatal(err)
				}
				scalars = append(scalars, rune(cp))
				if part == "@Part1" && i == 0 {
					covered[rune(cp)] = true
				}
			}
			text[i] = string(scalars)
		}
		for i, input := range text {
			want := text[1]
			if i >= 3 {
				want = text[3]
			}
			if got := r.normalize(input); got != want {
				t.Fatalf("UAX15 case %d column %d: %U != %U", count, i, []rune(got), []rune(want))
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 19074 {
		t.Fatalf("incomplete normalization corpus: %d", count)
	}
	// Normative Part1 complement: all other scalar values normalize unchanged.
	// Wire assignment is checked separately and rejects post-15.1 additions.
	for cp := rune(0); cp <= 0x10ffff; cp++ {
		if (cp >= 0xd800 && cp <= 0xdfff) || covered[cp] {
			continue
		}
		if r.normalize(string(cp)) != string(cp) {
			t.Fatalf("unlisted scalar changed: %U", cp)
		}
	}
	for _, cp := range []rune{-1, 0xd800, 0x110000, 0x1cc00} {
		if r.assigned(cp) {
			t.Fatalf("invalid or post-version scalar accepted: %U", cp)
		}
	}
	long := "A" + strings.Repeat("\u0315\u0300", 10000)
	if r.normalize(r.normalize(long)) != r.normalize(long) {
		t.Fatal("long combining run is not idempotent")
	}
	t.Log("19074 normalization cases and complete Part1 scalar complement passed")
}
