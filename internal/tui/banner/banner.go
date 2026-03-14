package banner

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// The main figlet banner in ANSI Shadow style.
var lines = [7]string{
	` ██╗      █████╗ ██████╗  █████╗ ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗`,
	` ██║     ██╔══██╗██╔══██╗██╔══██╗██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝`,
	` ██║     ███████║██████╔╝███████║██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   `,
	` ██║     ██╔══██║██╔══██╗██╔══██║██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   `,
	` ███████╗██║  ██║██║  ██║██║  ██║██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   `,
	` ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   `,
	``,
}

// Gradient colors — security-audit theme: deep blue/indigo to crimson.
var gradient = [6]string{
	"#42A5F5", // bright blue
	"#5C6BC0", // indigo
	"#7E57C2", // deep purple
	"#AB47BC", // purple
	"#E53935", // red
	"#FF7043", // deep orange
}

// Render returns the full colored banner with tagline and version.
func Render(version string) string {
	var b strings.Builder

	for i, line := range lines[:6] {
		style := lipgloss.NewStyle().Foreground(lipgloss.Color(gradient[i]))
		b.WriteString(style.Render(line))
		b.WriteByte('\n')
	}

	displayVersion := version
	if len(displayVersion) > 0 && displayVersion[0] == 'v' {
		displayVersion = displayVersion[1:]
	}
	tagline := lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#757575", Dark: "#9E9E9E"}).
		Italic(true).
		Render(fmt.Sprintf("  Laravel Security Audit Tool v%s", displayVersion))

	b.WriteString(tagline)
	b.WriteByte('\n')

	return b.String()
}

// RenderCompact returns a smaller single-line stylized logo for tight spaces.
func RenderCompact() string {
	l := lipgloss.NewStyle().Foreground(lipgloss.Color("#42A5F5")).Bold(true)
	i := lipgloss.NewStyle().Foreground(lipgloss.Color("#7E57C2")).Bold(true)

	return l.Render("Lara") + i.Render("inspect")
}

// ShieldIcon returns a small shield character for inline use.
func ShieldIcon() string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7E57C2")).
		Bold(true).
		Render("🛡")
}
