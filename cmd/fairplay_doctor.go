package cmd

import (
	"fmt"

	"github.com/majd/ipatool/v2/internal/fairplay"
	"github.com/spf13/cobra"
)

func fairplayDoctorCmd() *cobra.Command {
	var capture, ipa, model, reportPath string
	cmd := &cobra.Command{
		Use:   "fairplay-doctor",
		Short: "Diagnose FairPlay build, enrollment, SINF, and model compatibility",
		RunE: func(cmd *cobra.Command, args []string) error {
			report := fairplay.DoctorFairPlay(capture, ipa, model)
			if err := fairplay.WriteDoctorReport(reportPath, report); err != nil {
				return err
			}
			data, err := fairplay.MarshalDoctorReport(report)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(data))
			if !report.Ready {
				return fmt.Errorf("FairPlay diagnostics are not ready; see errors and next_actions")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&capture, "capture", "", "Private native enrollment capture directory")
	cmd.Flags().StringVar(&ipa, "ipa", "", "Personalized encrypted IPA")
	cmd.Flags().StringVar(&model, "model", "", "Enrollment model file or directory")
	cmd.Flags().StringVar(&reportPath, "report", "", "New private JSON diagnostic report")
	return cmd
}
