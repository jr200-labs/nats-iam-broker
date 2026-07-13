package broker

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"
	"text/template"

	"go.uber.org/zap"
)

func b64Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func sha256Hex(input string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(input)))
}

func trim(input string) string {
	return strings.TrimSpace(input)
}

func readFile(filePath string) (string, error) {
	resolvedFile := os.ExpandEnv(filePath)
	zap.L().Debug("filter:readFile", zap.String("path", resolvedFile))
	content, err := os.ReadFile(resolvedFile)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

// readNthLine reads the nth line of a file.
func readNthLine(n int, filePath string) (string, error) {
	zap.L().Debug("filter:readNthLine", zap.Int("line", n), zap.String("path", filePath))

	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	for i := 0; scanner.Scan(); i++ {
		if i == n-1 {
			return scanner.Text(), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", nil
}

func readEnv(envName string) string {
	return os.Getenv(envName)
}

func concat(input, suffix string) string {
	return input + suffix
}

func expandEnv(inputStr string) string {
	return os.ExpandEnv(inputStr)
}

func strJoin(input []interface{}, separators ...string) string {
	separator := ","
	if len(separators) > 0 && separators[0] != "" {
		separator = separators[0]
	}

	strList := make([]string, 0, len(input))
	for _, item := range input {
		strList = append(strList, fmt.Sprintf("%v", item))
	}
	return strings.Join(strList, separator)
}

// templateFuncMap returns the shared FuncMap for config templates.
func templateFuncMap() template.FuncMap {
	return template.FuncMap{
		"b64encode":   b64Encode,
		"sha256hex":   sha256Hex,
		"concat":      concat,
		"expandEnv":   expandEnv,
		"env":         readEnv,
		"readFile":    readFile,
		"readNthLine": readNthLine,
		"strJoin":     strJoin,
		"trim":        trim,
	}
}

// templateCache holds pre-compiled regex and templates for efficient re-rendering.
type templateCache struct {
	regex     *regexp.Regexp
	templates map[string]*template.Template
	params    ConfigParams
}

// newTemplateCache pre-compiles the template regex and all template expressions found in content.
func newTemplateCache(content string, params ConfigParams) *templateCache {
	pattern := fmt.Sprintf(`%s[^\n]*?%s`, regexp.QuoteMeta(params.LeftDelim), regexp.QuoteMeta(params.RightDelim))
	re := regexp.MustCompile(pattern)

	compiled := make(map[string]*template.Template)
	funcMap := templateFuncMap()

	for _, match := range re.FindAllString(content, -1) {
		if _, exists := compiled[match]; exists {
			continue
		}
		processed := unescapeYAMLTemplate(match)
		tmpl, err := template.New("config").
			Delims(params.LeftDelim, params.RightDelim).
			Funcs(funcMap).
			Parse(processed)
		if err != nil {
			zap.L().Warn("failed to pre-compile config template",
				zap.String("template", match), zap.Error(err))
			continue
		}
		compiled[match] = tmpl
	}

	return &templateCache{regex: re, templates: compiled, params: params}
}

// renderAll renders all template expressions in content using the pre-compiled cache.
func (tc *templateCache) renderAll(content string, mappings map[string]interface{}) string {
	matches := tc.regex.FindAllStringIndex(content, -1)

	result := content
	offset := 0

	for _, match := range matches {
		start, end := match[0]+offset, match[1]+offset
		originalMatch := result[start:end]

		var replacement string
		if tmpl, ok := tc.templates[originalMatch]; ok {
			replacement = executeTemplate(tmpl, originalMatch, mappings)
		} else {
			replacement = tryRenderTemplate(originalMatch, mappings, tc.params)
		}

		result = result[:start] + replacement + result[end:]
		offset += len(replacement) - (end - start)
	}

	return result
}

// executeTemplate runs a pre-compiled template with the given context.
func executeTemplate(tmpl *template.Template, input string, context map[string]interface{}) string {
	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, context); err != nil {
		zap.L().Debug("[render failed]", zap.String("input", input),
			zap.Any("context", context), zap.Error(err))
		return input
	}
	result := rendered.String()
	zap.L().Debug("[render ok]", zap.String("input", input),
		zap.String("result", SecureLogKey(result)))
	return result
}

// renderAllTemplates is the original uncached version, retained for backward compatibility in tests.
func renderAllTemplates(content string, mappings map[string]interface{}, params ConfigParams) string {
	tc := newTemplateCache(content, params)
	return tc.renderAll(content, mappings)
}

func unescapeYAMLTemplate(input string) string {
	// Unescape YAML double-quoted scalar escapes so template parser sees valid Go strings
	input = strings.ReplaceAll(input, `\"`, `"`)
	input = strings.ReplaceAll(input, `\\`, `\`)
	return input
}

func tryRenderTemplate(input string, context map[string]interface{}, params ConfigParams) string {
	processed := unescapeYAMLTemplate(input)

	tmpl, err := template.New("config").Delims(params.LeftDelim, params.RightDelim).Funcs(templateFuncMap()).Parse(processed)
	if err != nil {
		zap.L().Error("bad configuration template", zap.String("input", input), zap.Error(err))
		return input
	}

	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, context); err != nil {
		zap.L().Debug("[render failed]", zap.String("input", input), zap.Any("context", context), zap.Error(err))
		return input
	}

	result := rendered.String()
	zap.L().Debug("[render ok]", zap.String("input", input), zap.String("result", SecureLogKey(result)))
	return result
}
