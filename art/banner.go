package art

import (
	_ "embed"
	"strings"
)

//go:embed ascii.txt
var asciiBanner string

func Banner() string {
	return strings.TrimSpace(asciiBanner)
}
