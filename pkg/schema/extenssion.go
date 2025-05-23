package schema

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
	"xiaoshiai.cn/common/openapi"
)

var ExtraPropsHandlers = map[string]func(schema *openapi.Schema, sec Section){
	"schema":      SchemaOptionHandler,
	"param":       NoopOptionHandler, // ignore @param options
	"hidden":      HiddenOptionHandler,
	"order":       OrderOptionHandler,
	"title":       TitleOptionHandler,
	"x-enum":      XEnumOptionHandler,
	"description": DescriptionOptionHandler,
}

func CompleteFromCommentSection(schema *openapi.Schema, sec Section) error {
	if schema.ExtraProps == nil {
		schema.ExtraProps = map[string]any{}
	}
	key := strings.TrimPrefix(sec.Name, "@")
	if handler, ok := ExtraPropsHandlers[key]; ok && handler != nil {
		handler(schema, sec)
	} else {
		DefaultOptionHandler(schema, key, sec)
	}
	return nil
}

func SplitKeyLocale(key string) (string, string) {
	if i := strings.Index(key, "."); i > 0 {
		return key[:i], key[i+1:]
	}
	return key, ""
}

// nolint: gomnd
func ParseComment(comment string) []Section {
	if comment == "" {
		return nil
	}
	sections := []Section{}
	buf := bufio.NewReader(strings.NewReader(comment))
	for {
		line, _, err := buf.ReadLine()
		if err == io.EOF {
			break
		}
		if len(line) == 0 {
			continue
		}
		parser := Parser{Data: []byte(line)}

		thissections := parser.ParseSection()
		sections = append(sections, thissections...)
	}
	return sections
}

type Parser struct {
	Data []byte
	Pos  int
}

type Section struct {
	Raw     string
	Name    string
	Value   string
	Options []Option
}

type Option struct {
	Name  string
	Value string
}

// ParseSection parses the section from the comment.
// expr @<scetion> [value] [key=value]...
// example:
// @title test
// @description "a long description"
// @schema format=port;max=65535;min=1
func (p *Parser) ParseSection() []Section {
	for {
		b, ok := p.Read()
		if !ok {
			return nil
		}
		if b != '#' && b != ';' && b != ' ' {
			p.Rewind()
			break
		}
	}
	secname, _, _ := p.ReadIdentity()
	if len(secname) == 0 {
		return nil
	}
	if secname[0] != '@' {
		return nil
	}
	return p.parseSection(secname)
}

func (p *Parser) parseSection(secname []byte) []Section {
	sec := Section{
		Name: string(secname),
	}
	startpos := p.Pos
	for {
		// example:
		// type=number;format=port;max=65535;min=1
		// foo bar=a,b,c
		// desc="this is a test(abc)." foo=bar
		// @abc2
		// 123 @def 123=1
		key, c, ok := p.ReadIdentity()
		if len(key) == 0 {
			if !ok {
				break
			}
			continue
		}
		if key[0] == '@' {
			// end of this section
			// p.Rewind()
			sec.Raw = string(p.Data[startpos : p.Pos-len(key)-1])
			return append([]Section{sec}, p.parseSection(key)...)
		}
		if c == '=' {
			val, _, ok := p.ReadIdentity()
			sec.Options = append(sec.Options, Option{Name: string(key), Value: string(val)})
			if !ok {
				break
			}
		} else {
			if len(sec.Value) == 0 {
				sec.Value = string(key)
			} else {
				sec.Options = append(sec.Options, Option{Name: string(key), Value: ""})
			}
		}
	}
	sec.Raw = string(p.Data[startpos:p.Pos])
	return []Section{sec}
}

func (p *Parser) Rewind() {
	p.Pos--
	if p.Pos < 0 {
		p.Pos = 0
	}
}

func (p *Parser) Read() (byte, bool) {
	if p.Pos >= len(p.Data) {
		return 0, false
	}
	b := p.Data[p.Pos]
	p.Pos++
	return b, true
}

func (p *Parser) Until(b byte) ([]byte, bool) {
	start := p.Pos
	for {
		pp, ok := p.Read()
		if !ok {
			return nil, false
		}
		if pp == b {
			return p.Data[start : p.Pos-1], true
		}
	}
}

// ReadIdentity reads a string until it finds a space, comma, or parenthesis.
// example:
//
//	 @abc
//	"foo bar"
//	"foo,bar"
func (p *Parser) ReadIdentity() ([]byte, byte, bool) {
	start := p.Pos
	started := false
	var startch byte
	for {
		b, ok := p.Read()
		if !ok {
			return p.Data[start:p.Pos], 0, false
		}
		switch b {
		case '\'', '"', '`':
			if !started {
				started = true
				startch = b
				start = p.Pos
			} else {
				prevch := p.Data[p.Pos-1]
				// escape char
				if prevch == '\\' {
					continue
				}
				if startch == b {
					return p.Data[start : p.Pos-1], b, true
				}
			}
		case ';', '=':
			if startch == 0 {
				return p.Data[start : p.Pos-1], b, true
			}
		case ' ':
			if started && startch == 0 {
				return p.Data[start : p.Pos-1], b, true
			}
		default:
			if !started {
				started = true
				start = p.Pos - 1
			}
		}
	}
}

// nolint: gomnd
func SchemaOptionHandler(schema *openapi.Schema, sec Section) {
	for _, option := range sec.Options {
		SetSchemaProp(schema, option.Name, option.Value)
	}
}

func DefaultOptionHandler(schema *openapi.Schema, kind string, sec Section) {
	if sec.Value == "" && len(sec.Options) == 0 {
		SetSchemaProp(schema, kind, "true")
		return
	}
	if sec.Value != "" {
		SetSchemaProp(schema, kind, sec.Value)
		return
	}
	if len(sec.Options) == 0 {
		return
	}
	kvs := map[string]any{}
	for _, option := range sec.Options {
		kvs[option.Name] = formatYamlStr(option.Value)
	}
	if schema.ExtraProps == nil {
		schema.ExtraProps = map[string]any{}
	}
	schema.ExtraProps[kind] = kvs
}

// formatYamlStr convert "true" to bool(true), "123" => int(123)
func formatYamlStr(str string) any {
	if str == "" {
		return nil
	}
	into := map[string]any{}
	if err := yaml.Unmarshal([]byte("key: "+str), &into); err != nil {
		return str
	}
	return into["key"]
}

func NoopOptionHandler(schema *openapi.Schema, sec Section) {
}

type HiddenProps struct {
	Operator   HiddenPropsOperator `json:"operator,omitempty"`
	Conditions []HiddenCondition   `json:"conditions,omitempty"`
}

// Ref: https://github.com/kubegems/dashboard/blob/448f9c5767d4232adf4c86b711ae252f5a9e43de/src/views/appstore/components/DeployWizard/Param/index.vue#L160-L185
const (
	HiddenPropsOperatorOr  = "or"
	HiddenPropsOperatorAnd = "and"
	HiddenPropsOperatorNor = "nor"
	HiddenPropsOperatorNot = "not"
)

type HiddenPropsOperator string

type HiddenCondition struct {
	Path  string `json:"path"`
	Value any    `json:"value"`
}

func HiddenOptionHandler(schema *openapi.Schema, sec Section) {
	if sec.Value != "" {
		schema.ExtraProps["hidden"] = formatYamlStr(sec.Value)
		return
	}
	options := []Option{}
	var operatorOpetion Option
	for _, option := range sec.Options {
		if option.Name == "operator" {
			operatorOpetion = option
		} else {
			options = append(options, option)
		}
	}
	// convert map k=v to object type {path=jsonpath, value=value}
	operator := operatorOpetion.Value
	if len(options) == 0 {
		return
	}
	if len(options) == 1 {
		// simple type
		for _, option := range options {
			// case : foo!=bar key=foo!
			if strings.HasSuffix(option.Name, "!") {
				schema.ExtraProps["hidden"] = HiddenProps{
					Operator: HiddenPropsOperatorNot,
					Conditions: []HiddenCondition{
						{
							Path:  strings.TrimSuffix(option.Name, "!"),
							Value: formatYamlStr(option.Value),
						},
					},
				}
				return
			}
			schema.ExtraProps["hidden"] = HiddenCondition{Path: option.Name, Value: formatYamlStr(option.Value)}
			return
		}
	}
	if operator == "" {
		operator = HiddenPropsOperatorOr
	}
	props := HiddenProps{
		Operator: HiddenPropsOperator(operator),
	}
	for _, option := range options {
		props.Conditions = append(props.Conditions, HiddenCondition{Path: option.Name, Value: formatYamlStr(option.Value)})
	}
	schema.ExtraProps["hidden"] = props
}

// OrderOptionHandler handle properties order
// Ref: https://github.com/go-openapi/spec/blob/1005cfb91978aa416cfc5a1251b790126390788a/properties.go#L44
func OrderOptionHandler(schema *openapi.Schema, sec Section) {
	schema.Extensions["x-order"] = formatYamlStr(sec.Value)
}

func TitleOptionHandler(schema *openapi.Schema, sec Section) {
	DefaultOptionHandler(schema, "title", sec)
	// automate add @form=true when @title exists
	if schema.Title != "" {
		SetSchemaProp(schema, "form", "true")
	}
}

// nolint: gomnd,funlen
func SetSchemaProp(schema *openapi.Schema, k string, v any) {
	switch k {
	case "min", "minmum":
		schema.Minimum = anyToFloat(v)
	case "minLength", "minLen", "minlen":
		schema.MinLength = anyToInt(v)
	case "maxLength", "maxLen", "maxlen":
		schema.MaxLength = anyToInt(v)
	case "max", "maxmum":
		schema.Maximum = anyToFloat(v)
	case "format":
		schema.Format = anyToString(v)
	case "pattern":
		schema.Pattern = anyToString(v)
	case "required":
		schema.Required = strings.Split(anyToString(v), ",")
	case "default":
		schema.Default = formatYamlStr(anyToString(v))
	case "nullable":
		schema.Nullable = anyToBool(v)
	case "example":
		schema.Example = v
	case "title":
		schema.Title = anyToString(v)
	case "enum":
		enums := []any{}
		for item := range strings.SplitSeq(anyToString(v), ",") {
			enums = append(enums, formatYamlStr(item))
		}
		schema.Enum = enums
	case "description":
		schema.Description = anyToString(v)
	case "type":
		typestr := anyToString(v)
		if !schema.Type.Contains(typestr) {
			// use prepend
			if v != "null" {
				schema.Type = append([]string{typestr}, schema.Type...)
			} else {
				schema.Type = append(schema.Type, typestr)
			}
		}
	case "items":
		items := openapi.SchemaOrArray{}
		if err := json.Unmarshal([]byte(anyToString(v)), &items); err != nil {
			fmt.Printf("Unable decode schema items values: %s error: %s\n", v, err.Error())
		}
		schema.Items = items
	default:
		if schema.ExtraProps == nil {
			schema.ExtraProps = map[string]any{}
		}
		schema.ExtraProps[k] = formatExtraValue(anyToString(v))
	}
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func anyToFloat(v any) *float64 {
	if v == nil {
		return nil
	}
	fval, err := strconv.ParseFloat(anyToString(v), 32)
	if err != nil {
		return nil
	}
	return &fval
}

func anyToInt(v any) *int64 {
	if v == nil {
		return nil
	}
	ival, err := strconv.ParseInt(anyToString(v), 10, 64)
	if err != nil {
		return nil
	}
	return &ival
}

func anyToBool(v any) bool {
	return v == "true" || v == "1" || v == true
}

func formatExtraValue(v string) any {
	if v == "" {
		return nil
	}
	if v[0] == '{' || v[0] == '[' {
		var obj any
		if err := json.Unmarshal([]byte(v), &obj); err != nil {
			return v
		}
		return obj
	}
	return formatYamlStr(v)
}

func XEnumOptionHandler(schema *openapi.Schema, sec Section) {
	if schema.ExtraProps == nil {
		schema.ExtraProps = map[string]any{}
	}
	xenum := []map[string]any{}
	for _, option := range sec.Options {
		xenum = append(xenum, map[string]any{"text": option.Value, "value": formatYamlStr(option.Name)})
	}
	if _, ok := schema.ExtraProps["render"]; !ok {
		schema.ExtraProps["render"] = "radio"
	}
	schema.ExtraProps["x-enum"] = xenum
}

func DescriptionOptionHandler(schema *openapi.Schema, sec Section) {
	schema.Description = sec.Raw
}
