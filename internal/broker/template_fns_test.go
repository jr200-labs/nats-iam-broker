package broker

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestB64Encode(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "aGVsbG8="},
		{"", ""},
		{"hello world!", "aGVsbG8gd29ybGQh"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, b64Encode(tt.input))
	}
}

func TestTrim(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"  hello  ", "hello"},
		{"hello", "hello"},
		{"\t\n hello \n\t", "hello"},
		{"", ""},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, trim(tt.input))
	}
}

func TestConcat(t *testing.T) {
	assert.Equal(t, "helloworld", concat("hello", "world"))
	assert.Equal(t, "hello", concat("hello", ""))
	assert.Equal(t, "world", concat("", "world"))
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("TEST_EXPAND_VAR", "expanded")
	assert.Equal(t, "expanded", expandEnv("$TEST_EXPAND_VAR"))
	assert.Equal(t, "prefix-expanded-suffix", expandEnv("prefix-$TEST_EXPAND_VAR-suffix"))
	assert.Equal(t, "literal", expandEnv("literal"))
}

func TestReadEnv(t *testing.T) {
	t.Setenv("TEST_READ_ENV_VAR", "myvalue")
	assert.Equal(t, "myvalue", readEnv("TEST_READ_ENV_VAR"))
	assert.Equal(t, "", readEnv("NONEXISTENT_VAR_XYZ_12345"))
}

func TestStrJoin(t *testing.T) {
	tests := []struct {
		name       string
		input      []interface{}
		separators []string
		expected   string
	}{
		{
			name:     "default separator",
			input:    []interface{}{"a", "b", "c"},
			expected: "a,b,c",
		},
		{
			name:       "custom separator",
			input:      []interface{}{"a", "b", "c"},
			separators: []string{" | "},
			expected:   "a | b | c",
		},
		{
			name:     "mixed types",
			input:    []interface{}{"hello", 42, true},
			expected: "hello,42,true",
		},
		{
			name:     "empty input",
			input:    []interface{}{},
			expected: "",
		},
		{
			name:     "single element",
			input:    []interface{}{"only"},
			expected: "only",
		},
		{
			name:       "empty separator string falls back to default",
			input:      []interface{}{"a", "b"},
			separators: []string{""},
			expected:   "a,b",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := strJoin(tt.input, tt.separators...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReadFile(t *testing.T) {
	// Create a temp file
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("file content"), 0644))

	t.Run("existing file", func(t *testing.T) {
		content, err := readFile(filePath)
		require.NoError(t, err)
		assert.Equal(t, "file content", content)
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := readFile(filepath.Join(dir, "missing.txt"))
		assert.Error(t, err)
	})

	t.Run("with env var expansion", func(t *testing.T) {
		t.Setenv("TEST_READ_DIR", dir)
		content, err := readFile("$TEST_READ_DIR/test.txt")
		require.NoError(t, err)
		assert.Equal(t, "file content", content)
	})
}

func TestReadNthLine(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "lines.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("line1\nline2\nline3\n"), 0644))

	tests := []struct {
		name     string
		n        int
		expected string
	}{
		{"first line", 1, "line1"},
		{"second line", 2, "line2"},
		{"third line", 3, "line3"},
		{"beyond file", 10, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := readNthLine(tt.n, filePath)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := readNthLine(1, filepath.Join(dir, "missing.txt"))
		assert.Error(t, err)
	})
}

func TestUnescapeYAMLTemplate(t *testing.T) {
	assert.Equal(t, `he said "hello"`, unescapeYAMLTemplate(`he said \"hello\"`))
	assert.Equal(t, `path\to\file`, unescapeYAMLTemplate(`path\\to\\file`))
	assert.Equal(t, "no escapes", unescapeYAMLTemplate("no escapes"))
}

func TestRenderAllTemplates(t *testing.T) {
	params := ConfigParams{LeftDelim: "{{", RightDelim: "}}"}

	tests := []struct {
		name     string
		content  string
		mappings map[string]interface{}
		expected string
	}{
		{
			name:     "simple variable",
			content:  "hello {{.name}}",
			mappings: map[string]interface{}{"name": "world"},
			expected: "hello world",
		},
		{
			name:     "multiple variables",
			content:  "{{.greeting}} {{.name}}!",
			mappings: map[string]interface{}{"greeting": "hi", "name": "alice"},
			expected: "hi alice!",
		},
		{
			name:     "no templates",
			content:  "plain text",
			mappings: map[string]interface{}{},
			expected: "plain text",
		},
		{
			name:     "b64encode function",
			content:  `{{b64encode "hello"}}`,
			mappings: map[string]interface{}{},
			expected: "aGVsbG8=",
		},
		{
			name:     "sha256hex function",
			content:  `{{sha256hex "hello"}}`,
			mappings: map[string]interface{}{},
			expected: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:     "trim function",
			content:  `{{trim "  spaced  "}}`,
			mappings: map[string]interface{}{},
			expected: "spaced",
		},
		{
			name:     "concat function",
			content:  `{{concat "foo" "bar"}}`,
			mappings: map[string]interface{}{},
			expected: "foobar",
		},
		{
			name:     "missing field renders as no value",
			content:  "{{.missing_field}}",
			mappings: map[string]interface{}{},
			expected: "<no value>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := renderAllTemplates(tt.content, tt.mappings, params)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRenderAllTemplates_CustomDelimiters(t *testing.T) {
	params := ConfigParams{LeftDelim: "<<", RightDelim: ">>"}
	result := renderAllTemplates("hello <<.name>>", map[string]interface{}{"name": "world"}, params)
	assert.Equal(t, "hello world", result)
}

func TestNewTemplateCache(t *testing.T) {
	params := ConfigParams{LeftDelim: "{{", RightDelim: "}}"}

	t.Run("pre-compiles all template expressions", func(t *testing.T) {
		content := "url: {{.url}}\nname: {{.name}}\nstatic: plain"
		tc := newTemplateCache(content, params)

		assert.NotNil(t, tc.regex)
		assert.Len(t, tc.templates, 2)
		assert.Contains(t, tc.templates, "{{.url}}")
		assert.Contains(t, tc.templates, "{{.name}}")
	})

	t.Run("deduplicates identical templates", func(t *testing.T) {
		content := "a: {{.val}}\nb: {{.val}}\nc: {{.val}}"
		tc := newTemplateCache(content, params)

		assert.Len(t, tc.templates, 1)
		assert.Contains(t, tc.templates, "{{.val}}")
	})

	t.Run("no templates produces empty cache", func(t *testing.T) {
		tc := newTemplateCache("plain text with no templates", params)

		assert.NotNil(t, tc.regex)
		assert.Empty(t, tc.templates)
	})

	t.Run("invalid template is skipped", func(t *testing.T) {
		// {{.valid}} will compile, {{func_missing "x"}} will fail because func_missing isn't registered
		content := `{{.valid}} {{func_missing "x"}}`
		tc := newTemplateCache(content, params)

		// The valid one should be compiled, the invalid one skipped
		assert.Contains(t, tc.templates, "{{.valid}}")
	})

	t.Run("custom delimiters", func(t *testing.T) {
		customParams := ConfigParams{LeftDelim: "<<", RightDelim: ">>"}
		content := "hello <<.name>>"
		tc := newTemplateCache(content, customParams)

		assert.Len(t, tc.templates, 1)
		assert.Contains(t, tc.templates, "<<.name>>")
	})

	t.Run("pre-compiles function templates", func(t *testing.T) {
		content := `value: {{b64encode "hello"}}`
		tc := newTemplateCache(content, params)

		assert.Len(t, tc.templates, 1)
	})
}

func TestTemplateCache_RenderAll(t *testing.T) {
	params := ConfigParams{LeftDelim: "{{", RightDelim: "}}"}

	t.Run("renders using pre-compiled templates", func(t *testing.T) {
		content := "hello {{.name}}, email: {{.email}}"
		tc := newTemplateCache(content, params)

		result := tc.renderAll(content, map[string]interface{}{
			"name":  "alice",
			"email": "alice@test.com",
		})
		assert.Equal(t, "hello alice, email: alice@test.com", result)
	})

	t.Run("produces same output as uncached renderAllTemplates", func(t *testing.T) {
		content := `name: {{.name}}
url: {{.url}}
encoded: {{b64encode "test"}}
plain: no-template`

		mappings := map[string]interface{}{
			"name": "my-service",
			"url":  "nats://localhost:4222",
		}

		tc := newTemplateCache(content, params)
		cached := tc.renderAll(content, mappings)
		uncached := renderAllTemplates(content, mappings, params)

		assert.Equal(t, uncached, cached)
	})

	t.Run("renders with different mappings from same cache", func(t *testing.T) {
		content := "user: {{.user}}"
		tc := newTemplateCache(content, params)

		r1 := tc.renderAll(content, map[string]interface{}{"user": "alice"})
		r2 := tc.renderAll(content, map[string]interface{}{"user": "bob"})

		assert.Equal(t, "user: alice", r1)
		assert.Equal(t, "user: bob", r2)
	})

	t.Run("no templates returns content unchanged", func(t *testing.T) {
		content := "static content"
		tc := newTemplateCache(content, params)

		result := tc.renderAll(content, map[string]interface{}{})
		assert.Equal(t, "static content", result)
	})

	t.Run("missing field renders as no value", func(t *testing.T) {
		content := "{{.missing_field}}"
		tc := newTemplateCache(content, params)

		result := tc.renderAll(content, map[string]interface{}{})
		assert.Equal(t, "<no value>", result)
	})
}

func TestTemplateFuncMap(t *testing.T) {
	fm := templateFuncMap()
	expectedFuncs := []string{"b64encode", "concat", "expandEnv", "env", "readFile", "readNthLine", "sha256hex", "strJoin", "trim"}
	for _, name := range expectedFuncs {
		assert.Contains(t, fm, name, "templateFuncMap should contain %s", name)
	}
}

func TestTryRenderTemplate(t *testing.T) {
	params := ConfigParams{LeftDelim: "{{", RightDelim: "}}"}

	t.Run("valid template", func(t *testing.T) {
		result := tryRenderTemplate("{{.foo}}", map[string]interface{}{"foo": "bar"}, params)
		assert.Equal(t, "bar", result)
	})

	t.Run("invalid template syntax returns input", func(t *testing.T) {
		result := tryRenderTemplate("{{invalid syntax", map[string]interface{}{}, params)
		assert.Equal(t, "{{invalid syntax", result)
	})

	t.Run("missing field renders as no value", func(t *testing.T) {
		result := tryRenderTemplate("{{.missing}}", map[string]interface{}{}, params)
		assert.Equal(t, "<no value>", result)
	})
}
