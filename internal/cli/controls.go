package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/nagi1/larainspect/internal/controls"
	"github.com/nagi1/larainspect/internal/ux"
	"github.com/spf13/cobra"
)

func (app App) newControlsCommand() *cobra.Command {
	var outputFormat string
	var statuses []string
	var checkIDs []string

	cmd := &cobra.Command{
		Use:           "controls",
		Short:         "List normalized external security controls and their check mappings",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			normalizedStatuses, err := parseControlStatuses(statuses)
			if err != nil {
				return err
			}
			selectedControls := controls.Filter(normalizedStatuses, checkIDs)
			return renderControls(cmd.OutOrStdout(), selectedControls, outputFormat)
		},
	}

	cmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text or json")
	cmd.Flags().StringSliceVar(&statuses, "status", nil, "Filter by status: implemented, partial, queued, or out_of_scope")
	cmd.Flags().StringSliceVar(&checkIDs, "check-id", nil, "Filter to controls mapped to the given check ID; may be repeated")
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		printControlsHelp(cmd.OutOrStdout())
	})
	cmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return newUsageError(err, printControlsHelp)
	})

	return cmd
}

func parseControlStatuses(values []string) ([]controls.Status, error) {
	normalizedStatuses := make([]controls.Status, 0, len(values))

	for _, value := range values {
		status, ok := controls.NormalizeStatus(value)
		if !ok {
			return nil, newUsageError(
				fmt.Errorf("unsupported status %q (use implemented, partial, queued, or out_of_scope)", value),
				printControlsHelp,
			)
		}

		normalizedStatuses = append(normalizedStatuses, status)
	}

	return normalizedStatuses, nil
}

func renderControls(writer io.Writer, catalog []controls.Control, outputFormat string) error {
	switch strings.ToLower(strings.TrimSpace(outputFormat)) {
	case "", "text":
		return renderControlsText(writer, catalog)
	case "json":
		return renderControlsJSON(writer, catalog)
	default:
		return newUsageError(
			fmt.Errorf("unsupported controls format %q (use text or json)", outputFormat),
			printControlsHelp,
		)
	}
}

func renderControlsJSON(writer io.Writer, catalog []controls.Control) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(catalog)
}

func renderControlsText(writer io.Writer, catalog []controls.Control) error {
	if _, err := fmt.Fprintln(writer, "larainspect normalized control map"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "=============================="); err != nil {
		return err
	}
	if len(catalog) == 0 {
		_, err := fmt.Fprintln(writer, "No controls matched the current filters.")
		return err
	}

	for index, control := range catalog {
		if err := writeControlBlock(writer, index+1, control); err != nil {
			return err
		}
		if index < len(catalog)-1 {
			if _, err := fmt.Fprintln(writer); err != nil {
				return err
			}
		}
	}

	return nil
}

func writeControlBlock(writer io.Writer, index int, control controls.Control) error {
	if _, err := fmt.Fprintf(writer, "%d. %s [%s]\n", index, control.ID, control.Status); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "   Name: %s\n", control.Name); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "   Source Categories: %s\n", strings.Join(control.SourceCategories, ", ")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "   Evidence: %s\n", control.EvidenceType); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "   Checks: %s\n", formatControlChecks(control.CheckIDs)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "   Description: %s\n", control.Description); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "   Sources:"); err != nil {
		return err
	}

	for _, source := range control.Sources {
		if _, err := fmt.Fprintf(writer, "   - %s: %s\n", source.Title, source.URL); err != nil {
			return err
		}
	}

	if strings.TrimSpace(control.MissingWork) != "" {
		if _, err := fmt.Fprintf(writer, "   Missing Work: %s\n", control.MissingWork); err != nil {
			return err
		}
	}
	if strings.TrimSpace(control.OutOfScopeReason) != "" {
		if _, err := fmt.Fprintf(writer, "   Out Of Scope: %s\n", control.OutOfScopeReason); err != nil {
			return err
		}
	}

	return nil
}

func formatControlChecks(checkIDs []string) string {
	if len(checkIDs) == 0 {
		return "none"
	}

	return strings.Join(checkIDs, ", ")
}

func printControlsHelp(writer io.Writer) {
	fmt.Fprint(writer, strings.TrimSpace(ux.ControlsHelp()))
	fmt.Fprintln(writer)
}
