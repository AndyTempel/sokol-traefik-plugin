package sokol_traefik_plugin

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSharedTraefikPathNormalizationVectors(t *testing.T) {
	data, err := os.ReadFile(
		filepath.Join("testdata", "edge-normalization-v1.json"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		RequestPaths []struct {
			Input string `json:"input"`
			Error bool   `json:"error"`
		} `json:"request_path_cases"`
		RawPaths []struct {
			Input string `json:"input"`
			Error bool   `json:"error"`
		} `json:"raw_path_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, test := range vectors.RequestPaths {
		t.Run("path/"+test.Input, func(t *testing.T) {
			request := httptest.NewRequest("GET", "http://example.test/", nil)
			request.URL.Path = test.Input
			valid := validInboundMetadata(request)
			if valid == test.Error {
				t.Fatalf("valid=%v error_vector=%v", valid, test.Error)
			}
		})
	}
	for _, test := range vectors.RawPaths {
		t.Run("raw/"+test.Input, func(t *testing.T) {
			request := httptest.NewRequest(
				"GET",
				"http://example.test"+test.Input,
				nil,
			)
			valid := validInboundMetadata(request)
			if valid == test.Error {
				t.Fatalf(
					"path=%q raw_path=%q valid=%v error_vector=%v",
					request.URL.Path,
					request.URL.RawPath,
					valid,
					test.Error,
				)
			}
		})
	}
}
