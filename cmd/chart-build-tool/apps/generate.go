package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/spf13/cobra"
	"xiaoshiai.cn/build-tools/pkg/schema"
)

const DefaultFilePerm = 0o755

func NewSchemaGenerateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Build chart from source",
		Args:  cobra.MinimumNArgs(1),
		Long: `
		Example:
		chart-build-tool generate ./charts/mychart
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
			defer cancel()
			go func() {
				<-ctx.Done()
				os.Exit(1)
			}()
			allcharts := []string{}
			doprocss := func(path string) error {
				allcharts = append(allcharts, path)
				log.Printf("Found chart %s", path)
				return nil
			}
			if err := WalkAllCharts(args, doprocss); err != nil {
				fmt.Print(err.Error())
				os.Exit(1)
			}

			for _, chartpath := range allcharts {
				if err := GenerateWriteSchema(chartpath, schema.Options{}); err != nil {
					return err
				}
			}
			return nil
		},
	}
	return cmd
}

func GenerateWriteSchema(chartpath string, options schema.Options) error {
	if filepath.Base(chartpath) == "values.yaml" {
		chartpath = filepath.Dir(chartpath)
	}
	valuesfile := filepath.Join(chartpath, "values.yaml")
	fmt.Printf("Reading %s\n", valuesfile)
	valuecontent, err := os.ReadFile(valuesfile)
	if err != nil {
		return err
	}
	item, err := schema.GenerateSchema(valuecontent)
	if err != nil {
		return err
	}
	i18nschemas, err := schema.CompleteI18n(*item)
	if err != nil {
		return err
	}
	for lang, langschema := range i18nschemas.Locales {
		filename := filepath.Join(chartpath, options.I18nDirectory, fmt.Sprintf("values.schema.%s.json", lang))
		if !options.IncludeAll {
			schema.PurgeSchema(langschema)
		}
		if langschema.Empty() {
			fmt.Printf("Empty schema of i18n %s schema\n", lang)
			return nil
		}
		if err := WriteJson(filename, langschema); err != nil {
			return err
		}
	}
	if !options.IncludeAll {
		schema.PurgeSchema(i18nschemas.Orignal)
	}
	if i18nschemas.Orignal.Empty() {
		fmt.Printf("Empty schema")
		return nil
	}
	return WriteJson(filepath.Join(chartpath, "values.schema.json"), i18nschemas.Orignal)
}

func WriteJson(filename string, data any) error {
	schemacontent, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filename), DefaultFilePerm); err != nil {
		return err
	}
	fmt.Printf("Writing %s\n", filename)
	return os.WriteFile(filename, schemacontent, DefaultFilePerm)
}
