package schema

import (
	"fmt"

	"github.com/mitchellh/copystructure"
	"xiaoshiai.cn/common/openapi"
)

type Options struct {
	// parse all schema include not titled
	IncludeAll    bool
	I18nDirectory string
}

func PurgeSchema(schema *openapi.Schema) {
	if schema == nil {
		return
	}
	var purgedProperties openapi.SchemaProperties
	for _, item := range schema.Properties {
		if item.Schema.Title == "" {
			continue
		} else {
			PurgeSchema(&item.Schema)
			purgedProperties = append(purgedProperties, item)
		}
	}
	schema.Properties = purgedProperties
	PurgeSchema(schema.Items)
}

func CompleteI18n(schema openapi.Schema) (*I18nSchema, error) {
	i18nschemas, err := CompleteI18nFromComment(schema, schema.Comment)
	if err != nil {
		return nil, err
	}

	subi18nschemas, err := CompleteI18n(*i18nschemas.Orignal.Items)
	if err != nil {
		return nil, err
	}

	properties := make([]I18nSchema, len(i18nschemas.Orignal.Properties))
	for i, item := range i18nschemas.Orignal.Properties {
		subi18nschemas, err := CompleteI18n(item.Schema)
		if err != nil {
			return nil, err
		}
		properties[i] = *subi18nschemas
	}

	// must make  i18nschemas.Orignal's properties updated fully before deepcopy it.
	i18nschemas.Orignal.Items = subi18nschemas.Orignal
	for i, subi18nschemas := range properties {
		i18nschemas.Orignal.Properties[i].Schema = *subi18nschemas.Orignal
	}

	for locale, subi18nschema := range subi18nschemas.Locales {
		if _, ok := i18nschemas.Locales[locale]; !ok {
			i18nschemas.Locales[locale] = DeepCopySchema(i18nschemas.Orignal)
		}
		i18nschemas.Locales[locale].Items = subi18nschema
	}
	for locale := range i18nschemas.Locales {
		if _, ok := subi18nschemas.Locales[locale]; !ok {
			i18nschemas.Locales[locale] = subi18nschemas.Orignal
		}
	}
	for i, subi18nschemas := range properties {
		for locale, subi18nschema := range subi18nschemas.Locales {
			if _, ok := i18nschemas.Locales[locale]; !ok {
				i18nschemas.Locales[locale] = DeepCopySchema(i18nschemas.Orignal)
			}
			i18nschemas.Locales[locale].Properties[i].Schema = *subi18nschema
		}
		for locale := range i18nschemas.Locales {
			if _, ok := subi18nschemas.Locales[locale]; !ok {
				i18nschemas.Locales[locale].Properties[i].Schema = *subi18nschemas.Orignal
			}
		}
	}
	return i18nschemas, nil
}

type I18nSchema struct {
	Orignal *openapi.Schema
	Locales map[string]*openapi.Schema
}

func CompleteI18nFromComment(schema openapi.Schema, comment string) (*I18nSchema, error) {
	nolocale := []Section{}
	bylocale := map[string][]Section{}
	for _, sec := range ParseComment(comment) {
		key, locale := SplitKeyLocale(sec.Name)
		if locale != "" {
			sec.Name = key // reset section name to no locate
			bylocale[locale] = append(bylocale[locale], sec)
		} else {
			nolocale = append(nolocale, sec)
		}
	}

	var errs []error
	nolocaleschema := DeepCopySchema(&schema)
	for _, sec := range nolocale {
		if err := CompleteFromCommentSection(nolocaleschema, sec); err != nil {
			errs = append(errs, err)
		}
	}
	localeschemas := map[string]*openapi.Schema{}
	for locale, secs := range bylocale {
		localeSchema := DeepCopySchema(nolocaleschema)
		for _, sec := range secs {
			if err := CompleteFromCommentSection(localeSchema, sec); err != nil {
				errs = append(errs, err)
			}
		}
		localeschemas[locale] = localeSchema
	}
	return &I18nSchema{Orignal: nolocaleschema, Locales: localeschemas}, CombineErrors(errs...)
}

func DeepCopySchema(in *openapi.Schema) *openapi.Schema {
	out, err := copystructure.Copy(in)
	if err != nil {
		panic(err)
	}
	// nolint: forcetypeassert
	return out.(*openapi.Schema)
}

func CombineErrors(errs ...error) error {
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("%v", errs)
}
