package yaegi_test

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
)

func TestTraefikEmbeddedYaegiLoadsPluginContract(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	pluginRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	goPath := t.TempDir()
	interpretedRoot := filepath.Join(
		goPath, "src", "git.ksoft.tech", "ksoft", "sokol-traefik-plugin",
	)
	if err := os.MkdirAll(interpretedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(pluginRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pluginRoot, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(interpretedRoot, entry.Name()), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	interpreter := interp.New(interp.Options{GoPath: goPath})
	if err := interpreter.Use(stdlib.Symbols); err != nil {
		t.Fatal(err)
	}
	if _, err := interpreter.Eval(
		`import sokol "git.ksoft.tech/ksoft/sokol-traefik-plugin"`,
	); err != nil {
		t.Fatalf("Yaegi could not interpret plugin source: %v", err)
	}
	createConfig, err := interpreter.Eval("sokol.CreateConfig")
	if err != nil {
		t.Fatalf("CreateConfig is not exported through the interpreted package: %v", err)
	}
	if createConfig.Kind() != reflect.Func || createConfig.Type().NumIn() != 0 || createConfig.Type().NumOut() != 1 {
		t.Fatalf("unexpected CreateConfig signature: %s", createConfig.Type())
	}
	config := createConfig.Call(nil)[0]
	if config.IsNil() {
		t.Fatal("CreateConfig returned nil")
	}
	newMiddleware, err := interpreter.Eval("sokol.New")
	if err != nil {
		t.Fatalf("New is not exported through the interpreted package: %v", err)
	}
	if newMiddleware.Kind() != reflect.Func || newMiddleware.Type().NumIn() != 4 ||
		newMiddleware.Type().NumOut() != 2 {
		t.Fatalf("unexpected New signature: %s", newMiddleware.Type())
	}
}

func TestPluginRuntimeHasNoNonStandardImports(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	pluginRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	entries, err := os.ReadDir(pluginRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pluginRoot, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(content), `"git.ksoft.tech/`) ||
			strings.Contains(string(content), `"github.com/`) ||
			strings.Contains(string(content), `"golang.org/`) {
			t.Fatalf("%s imports a non-standard runtime package", entry.Name())
		}
	}
}
