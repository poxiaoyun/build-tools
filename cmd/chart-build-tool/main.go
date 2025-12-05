package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"xiaoshiai.cn/build-tools/cmd/chart-build-tool/apps"
)

func main() {
	cmd := cobra.Command{
		Use:   "chart-build-tool",
		Short: "Build and push helm chart",
	}
	cmd.AddCommand(apps.NewBuildCommand())
	cmd.AddCommand(apps.NewPushCommand())
	cmd.AddCommand(apps.NewSchemaGenerateCommand())
	if err := cmd.Execute(); err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
}
