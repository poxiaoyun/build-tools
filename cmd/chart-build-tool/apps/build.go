package apps

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/downloader"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/pusher"
	"helm.sh/helm/v3/pkg/registry"
	"helm.sh/helm/v3/pkg/repo"
)

func NewBuilCommand() *cobra.Command {
	options := BuildOptions{
		OutPut: "build",
	}
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build chart from source",
		Args:  cobra.MinimumNArgs(1),
		Long: `
		Example:
		chart-build-tool build --output build --replace myregistry.com=registry.hub.docker.com ./charts
		`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
			defer cancel()
			go func() {
				<-ctx.Done()
				os.Exit(1)
			}()
			return Build(ctx, args, options)
		},
	}
	cmd.Flags().StringVarP(&options.OutPut, "output", "o", options.OutPut, "Output directory")
	cmd.Flags().StringSliceVar(&options.Replaces, "replace", nil, "Replace value in values.yaml")
	return cmd
}

type BuildOptions struct {
	OutPut   string
	Replaces []string
}

type ValueReplace struct {
	Old string
	New string
}

func Build(ctx context.Context, pathes []string, options BuildOptions) error {
	var replaces []ValueReplace
	for _, replace := range options.Replaces {
		parts := strings.Split(replace, "=")
		if len(parts) != 2 {
			return fmt.Errorf("Invalid registry override: %s", replace)
		}
		replaces = append(replaces, ValueReplace{Old: parts[0], New: parts[1]})
	}

	allcharts := []string{}
	doprocss := func(path string) error {
		allcharts = append(allcharts, path)
		log.Printf("Found chart %s", path)
		return nil
	}
	if err := WalkAllCharts(pathes, doprocss); err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}
	for _, chartpath := range allcharts {
		log.Printf("Processing %s", chartpath)
		// build chart
		built, err := BuildChart(ctx, chartpath, options.OutPut, replaces)
		if err != nil {
			return err
		}
		allcharts = append(allcharts, built)
	}
	return nil
}

func WalkAllCharts(dirs []string, fn func(string) error) error {
	for _, dir := range dirs {
		matches, err := filepath.Glob(dir)
		if err != nil {
			return err
		}
		for _, match := range matches {
			if err := WalkChart(match, fn); err != nil {
				return err
			}
		}
	}
	return nil
}

func WalkChart(dir string, fn func(string) error) error {
	return filepath.Walk(dir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return nil
		}
		if strings.HasPrefix(info.Name(), ".") {
			return filepath.SkipDir
		}
		chartfiles := []string{"Chart.yaml", "source.yaml"}
		for _, chartfile := range chartfiles {
			if Exists(filepath.Join(path, chartfile)) {
				if err := fn(path); err != nil {
					return err
				}
				return filepath.SkipDir
			}
		}
		return nil
	})
}

func BuildChart(ctx context.Context, dir string, output string, replaces []ValueReplace) (string, error) {
	sourcefile := filepath.Join(dir, SourceFile)
	var chart *chart.Chart
	if Exists(sourcefile) {
		newchart, err := BuildChartFromSource(ctx, dir, sourcefile, output)
		if err != nil {
			return "", err
		}
		chart = newchart
	} else {
		newchart, err := loader.LoadDir(dir)
		if err != nil {
			return "", err
		}
		chart = newchart
	}
	// export chart to output
	chart, err := OverrideChart(ctx, chart, replaces)
	if err != nil {
		return "", err
	}
	log.Printf("Building dependencies for %s", chart.Name())
	chart, err = BuildDependencies(chart, output)
	if err != nil {
		return "", err
	}
	log.Printf("Packaging %s", chart.Name())
	tgzfile, err := chartutil.Save(chart, output)
	if err != nil {
		return "", err
	}
	log.Printf("Chart %s is saved to %s", chart.Name(), tgzfile)
	return tgzfile, nil
}

// OverrideChart may be used to override the chart before packaging
// it may update the values.yaml, Chart.yaml, etc.
func OverrideChart(ctx context.Context, chart *chart.Chart, replaces []ValueReplace) (*chart.Chart, error) {
	for _, raw := range chart.Raw {
		if raw.Name == chartutil.ValuesfileName {
			if err := OverrideValuesFile(ctx, raw, replaces); err != nil {
				return nil, err
			}
		}
	}
	return chart, nil
}

func OverrideValuesFile(ctx context.Context, file *chart.File, replaces []ValueReplace) error {
	node := &yaml.Node{}
	if err := yaml.Unmarshal(file.Data, node); err != nil {
		return err
	}
	overrideValueFunc(node, "", func(jsonpath, val string) string {
		candidates := []string{".image.repository", ".image.registry"}
		for _, candidate := range candidates {
			if strings.HasSuffix(jsonpath, candidate) {
				for _, replace := range replaces {
					if !strings.Contains(val, replace.Old) {
						continue
					}
					newval := strings.Replace(val, replace.Old, replace.New, -1)
					log.Printf("Overrided %s with %s at %s", val, newval, jsonpath)
					val = newval
				}
			}
		}
		return val
	})
	bts, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	file.Data = bts
	return nil
}

func overrideValueFunc(node *yaml.Node, keyprefix string, fn func(jsonpath, val string) string) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key, val := node.Content[i], node.Content[i+1]
			overrideValueFunc(val, keyprefix+"."+key.Value, fn)
		}
	case yaml.SequenceNode:
		for i, val := range node.Content {
			overrideValueFunc(val, fmt.Sprintf("%s[%d]", keyprefix, i), fn)
		}
	case yaml.ScalarNode:
		node.Value = fn(keyprefix, node.Value)
	case yaml.DocumentNode:
		overrideValueFunc(node.Content[0], keyprefix, fn)
	}
}

const SourceFile = "source.yaml"

type ChartSource struct {
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Repository string `json:"repository,omitempty"`
}

func BuildChartFromSource(ctx context.Context, chartdir string, sourcefile string, output string) (*chart.Chart, error) {
	// download chart from repository specified in source.yaml
	bts, err := os.ReadFile(sourcefile)
	if err != nil {
		return nil, err
	}
	src := &ChartSource{}
	if err := yaml.Unmarshal(bts, src); err != nil {
		return nil, err
	}
	if src.Repository == "" {
		return nil, fmt.Errorf("%s does't have repository", sourcefile)
	}
	if src.Name == "" {
		return nil, fmt.Errorf("%s does't have name", sourcefile)
	}
	log.Printf("Loading chart %s:%s from %s", src.Name, src.Version, src.Repository)
	rawfiles, err := LoadChart(ctx, src.Repository, src.Name, src.Version)
	if err != nil {
		return nil, err
	}
	chart, err := loader.LoadFiles(rawfiles)
	if err != nil {
		return nil, err
	}
	log.Printf("Saving chart %s", chart.Name())
	if err := chartutil.SaveDir(chart, output); err != nil {
		return nil, err
	}
	rawfilesmap := make(map[string][]byte)
	for _, rawfile := range rawfiles {
		rawfilesmap[rawfile.Name] = rawfile.Data
	}
	log.Printf("Merging files...")
	// merge all files in this directory into the chart
	fsys := os.DirFS(chartdir)
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || path == SourceFile {
			return nil
		}
		// merge
		log.Printf("Merging %s ...", path)
		filecontent, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		// only allow merge at root level
		if !strings.Contains(path, "/") {
			ext := filepath.Ext(path)
			switch ext {
			case ".yaml", ".yml":
				filecontent, err = MergeYamlFile(rawfilesmap[path], filecontent)
				if err != nil {
					return err
				}
			case ".json":
				// filecontent, err = MergeJsonFile(rawfilesmap[path], filecontent)
				// if err != nil {
				// 	return err
				// }
			}
		}
		// overrride the existing file
		rawfilesmap[path] = filecontent
		return nil
	}); err != nil {
		return nil, err
	}
	rawfiles = make([]*loader.BufferedFile, 0, len(rawfilesmap))
	for name, data := range rawfilesmap {
		rawfiles = append(rawfiles, &loader.BufferedFile{Name: name, Data: data})
	}
	return loader.LoadFiles(rawfiles)
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func MergeJsonFile(src, patch []byte) ([]byte, error) {
	if src == nil {
		return patch, nil
	}
	var srcval, patchval map[string]any
	if err := json.Unmarshal(src, &srcval); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(patch, &patchval); err != nil {
		return nil, err
	}
	merged, err := MergeValues(srcval, patchval)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(merged, "", "  ")
}

func MergeValues(src, patch map[string]any) (any, error) {
	return mergeValues(src, patch), nil
}

func mergeValues(dest, src map[string]any) map[string]any {
	if dest == nil {
		return src
	}
	for k, v := range src {
		if destv, ok := dest[k]; ok {
			switch val := destv.(type) {
			case map[string]any:
				switch patchval := v.(type) {
				case map[string]any:
					dest[k] = mergeValues(val, patchval)
				default:
					dest[k] = v
				}
			default:
				dest[k] = v
			}
		} else {
			dest[k] = v
		}
	}
	return dest
}

func MergeYamlFile(src, patch []byte) ([]byte, error) {
	if src == nil {
		return patch, nil
	}
	var srcval, patchval yaml.Node
	if err := yaml.Unmarshal(src, &srcval); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(patch, &patchval); err != nil {
		return nil, err
	}
	merged, err := MergeYamlNode(".", &srcval, &patchval)
	if err != nil {
		return nil, err
	}
	return yaml.Marshal(merged)
}

func MergeYamlNode(jsonpath string, src, patch *yaml.Node) (*yaml.Node, error) {
	if src == nil {
		return patch, nil
	}
	if patch == nil {
		return src, nil
	}
	if src.Kind != patch.Kind {
		return nil, fmt.Errorf("cannot merge %d with %d at %s", src.Kind, patch.Kind, jsonpath)
	}
	switch src.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(patch.Content); i += 2 {
			key, val := patch.Content[i], patch.Content[i+1]
			var srcval *yaml.Node
			for j := 0; j < len(src.Content); j += 2 {
				if src.Content[j].Value == key.Value {
					srcval = src.Content[j+1]
					break
				}
			}
			if srcval == nil {
				src.Content = append(src.Content, key, val)
			} else {
				newval, err := MergeYamlNode(jsonpath+"."+key.Value, srcval, val)
				if err != nil {
					return nil, err
				}
				srcval = newval
			}
		}
		return src, nil
	case yaml.SequenceNode:
		src.Content = patch.Content
		return src, nil
	case yaml.ScalarNode:
		src.Value = patch.Value
		return src, nil
	case yaml.DocumentNode:
		return MergeYamlNode(jsonpath, src.Content[0], patch.Content[0])
	default:
		return nil, fmt.Errorf("cannot merge %d", src.Kind)
	}
}

type HelmSetting struct {
	Out                   io.Writer
	Settigns              *cli.EnvSettings
	RepositoryConfig      string
	RepositoryCache       string
	RegistryClient        *registry.Client
	Getters               getter.Providers
	GettersOptions        []getter.Option
	Pushers               pusher.Providers
	PushersOptions        []pusher.Option
	Debug                 bool
	Verify                downloader.VerificationStrategy
	InsecureSkipVerifyTLS bool
}

func BuildDependencies(chart *chart.Chart, output string) (*chart.Chart, error) {
	if err := chartutil.SaveDir(chart, output); err != nil {
		return nil, err
	}
	chartdir := filepath.Join(output, chart.Name())
	// build dependencies
	settings := GetHelmSettings()
	man := &downloader.Manager{
		Out:              settings.Out,
		ChartPath:        chartdir,
		Getters:          settings.Getters,
		RegistryClient:   settings.RegistryClient,
		RepositoryConfig: settings.RepositoryConfig,
		RepositoryCache:  settings.RepositoryCache,
		Debug:            settings.Debug,
		Verify:           settings.Verify,
	}
	if err := man.Update(); err != nil {
		return nil, err
	}
	return loader.LoadDir(chartdir)
}

func LoadChart(ctx context.Context, repourl, name, version string) ([]*loader.BufferedFile, error) {
	settings := GetHelmSettings()
	dl := downloader.ChartDownloader{
		Out:              settings.Out,
		Getters:          settings.Getters,
		RepositoryConfig: settings.RepositoryConfig,
		RepositoryCache:  settings.RepositoryCache,
		RegistryClient:   settings.RegistryClient,
		Options:          settings.GettersOptions,
		Verify:           settings.Verify,
	}
	if !registry.IsOCI(repourl) {
		chartURL, err := repo.FindChartInAuthAndTLSAndPassRepoURL(
			repourl,
			"", "", // username password
			name, version,
			"", "", "", // cert key ca
			settings.InsecureSkipVerifyTLS,
			false, // passCredentialsAll
			dl.Getters)
		if err != nil {
			return nil, err
		}
		repourl = chartURL
	}
	u, err := dl.ResolveChartVersion(repourl, version)
	if err != nil {
		return nil, err
	}
	g, err := dl.Getters.ByScheme(u.Scheme)
	if err != nil {
		return nil, err
	}
	data, err := g.Get(u.String(), dl.Options...)
	if err != nil {
		return nil, err
	}
	return loader.LoadArchiveFiles(data)
}

type LogOut struct{}

func (l LogOut) Write(p []byte) (n int, err error) {
	log.Print(string(p))
	return len(p), nil
}

func GetHelmSettings() HelmSetting {
	out := LogOut{}
	settings := cli.New()
	registryClient, err := registry.NewClient(
		registry.ClientOptDebug(settings.Debug),
		registry.ClientOptWriter(out),
		registry.ClientOptCredentialsFile(settings.RegistryConfig),
	)
	if err != nil {
		log.Fatalf("Failed to create registry client: %v", err)
	}
	// cannot set to true,it's a bug in helm getter,it cause get tgz from github.com return 404.
	insecureSkipVerifyTLS := false
	return HelmSetting{
		Out:                   out,
		Settigns:              settings,
		RepositoryConfig:      settings.RepositoryConfig,
		RepositoryCache:       settings.RepositoryCache,
		RegistryClient:        registryClient,
		Verify:                downloader.VerifyNever,
		Debug:                 settings.Debug,
		InsecureSkipVerifyTLS: insecureSkipVerifyTLS,
		Getters:               getter.All(settings),
		GettersOptions: []getter.Option{
			getter.WithInsecureSkipVerifyTLS(insecureSkipVerifyTLS),
			getter.WithPlainHTTP(true),
			getter.WithRegistryClient(registryClient),
		},
		Pushers: pusher.All(settings),
		PushersOptions: []pusher.Option{
			pusher.WithInsecureSkipTLSVerify(insecureSkipVerifyTLS),
			pusher.WithPlainHTTP(true),
			pusher.WithRegistryClient(registryClient),
		},
	}
}
