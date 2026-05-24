package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

type Fingerprint struct {
	Hex string
}

type Wordlists struct {
	English []string
	Persian []string
}

type RenderedFingerprint struct {
	Hex    string
	EN     string
	FA     string
	Visual string
}

func PublisherFingerprint(pub []byte) Fingerprint {
	sum := sha256.Sum256(pub)
	return Fingerprint{Hex: hex.EncodeToString(sum[:])}
}

func RenderFingerprint(fp Fingerprint, wordlists Wordlists) (RenderedFingerprint, error) {
	bytes, err := hex.DecodeString(fp.Hex)
	if err != nil {
		return RenderedFingerprint{}, err
	}
	if len(bytes) < 6 {
		return RenderedFingerprint{}, fmt.Errorf("fingerprint too short")
	}
	return RenderedFingerprint{
		Hex:    fp.Hex,
		EN:     renderWords(bytes, wordlists.English),
		FA:     renderWords(bytes, wordlists.Persian),
		Visual: renderVisual(bytes),
	}, nil
}

func renderWords(bytes []byte, words []string) string {
	if len(words) == 0 {
		return ""
	}
	indexes := []int{
		int(bytes[0])<<3 | int(bytes[1])>>5,
		(int(bytes[1])&0x1f)<<6 | int(bytes[2])>>2,
		(int(bytes[2])&0x03)<<9 | int(bytes[3])<<1 | int(bytes[4])>>7,
		(int(bytes[4])&0x7f)<<4 | int(bytes[5])>>4,
	}
	out := make([]string, len(indexes))
	for i, idx := range indexes {
		out[i] = words[idx%len(words)]
	}
	return strings.Join(out, "-")
}

func renderVisual(bytes []byte) string {
	palette := []string{"#1b1b1b", "#0072b2", "#e69f00", "#009e73", "#cc79a7"}
	var b strings.Builder
	b.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50">`)
	for i := 0; i < 25; i++ {
		color := palette[int(bytes[i%len(bytes)])%len(palette)]
		x := (i % 5) * 10
		y := (i / 5) * 10
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="10" height="10" fill="%s"/>`, x, y, color))
	}
	b.WriteString(`</svg>`)
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(b.String()))
}
