package components

import (
	"strings"

	"github.com/nagi1/larainspect/internal/model"
	"github.com/nagi1/larainspect/internal/tui/theme"
)

// RenderSeverityBadge renders a colored badge like " CRITICAL " or " HIGH ".
func RenderSeverityBadge(sev model.Severity, t *theme.Theme) string {
	style, ok := t.SeverityStyles[sev]
	if !ok {
		return string(sev)
	}
	return style.Render(strings.ToUpper(theme.SeverityLabel(sev)))
}
