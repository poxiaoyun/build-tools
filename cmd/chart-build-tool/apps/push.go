package apps

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"helm.sh/helm/v3/pkg/uploader"
)

func NewPushCommand() *cobra.Command {
	options := PushOptions{}
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Push chart to chart registry",
		Long: `
Example:
	chart-build-tool push --username <username> --password <password> './build/*.tgz' https://charts.example.com

	chart-build-tool push --username <username> --password <password> './build/*.tgz' oci://registry.example.com/charts
		`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
			defer cancel()
			src, dest := args[0], args[1]
			return Push(ctx, src, dest, options)
		},
	}
	cmd.Flags().StringVarP(&options.Username, "username", "u", "", "Username for registry")
	cmd.Flags().StringVarP(&options.Password, "password", "p", "", "Password for registry")
	return cmd
}

type PushOptions struct {
	Username string
	Password string
}

func Push(ctx context.Context, src string, dest string, options PushOptions) error {
	files, err := filepath.Glob(src)
	if err != nil {
		return err
	}
	for _, file := range files {
		if !strings.HasSuffix(file, ".tgz") {
			continue
		}
		log.Printf("Pushing %s to %s", file, dest)
		if err := PushChart(ctx, file, dest, options); err != nil {
			return err
		}
	}
	return nil
}

func PushChart(ctx context.Context, tgzfile string, registry string, options PushOptions) error {
	if strings.HasPrefix(registry, "oci://") {
		return PushChartOCI(ctx, tgzfile, registry, options)
	}
	return PushChartHTTP(ctx, tgzfile, registry, options)
}

func PushChartOCI(ctx context.Context, tgzfile string, registry string, options PushOptions) error {
	settings := GetHelmSettings()
	c := uploader.ChartUploader{
		Out:     settings.Out,
		Pushers: settings.Pushers,
		Options: settings.PushersOptions,
	}
	return c.UploadTo(tgzfile, registry)
}

func PushChartHTTP(ctx context.Context, tgzfile string, registry string, options PushOptions) error {
	ioFile, err := os.Open(tgzfile)
	if err != nil {
		return err
	}
	defer ioFile.Close()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registry, ioFile)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/tar+gzip")
	if options.Username != "" && options.Password != "" {
		req.SetBasicAuth(options.Username, options.Password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("push chart failed: %d %s", resp.StatusCode, string(body))
	}
	return nil
}
