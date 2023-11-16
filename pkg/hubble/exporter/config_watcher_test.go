// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestYamlConfigFileUnmarshalling(t *testing.T) {

	// given
	file := createTestConfigFile(t)

	sut := configWatcher{configFilePath: file.Name()}

	// when
	config, hash, err := sut.readConfig()
	assert.NoError(t, err)

	// then
	assert.Equal(t, 3, len(config.FlowLogs))

	assert.Equal(t, uint64(0xbcaaf36594dd2b1b), hash)

	expectedDate := time.Date(2023, 10, 9, 23, 59, 59, 0, time.FixedZone("", -7*60*60))

	expectedConfigs := []FlowLogConfig{
		{
			Name:           "test001",
			FilePath:       "/var/log/network/flow-log/pa/test001.log",
			FieldMask:      FieldMask{},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{},
			End:            &expectedDate,
		},
		{
			Name:      "test002",
			FilePath:  "/var/log/network/flow-log/pa/test002.log",
			FieldMask: FieldMask{"source.namespace", "source.pod_name", "destination.namespace", "destination.pod_name", "verdict"},
			IncludeFilters: FlowFilters{
				{
					SourcePod: []string{"default/"},
					EventType: []*flow.EventTypeFilter{
						{Type: 1},
					},
				},
				{
					DestinationPod: []string{"frontend/nginx-975996d4c-7hhgt"},
				},
			},
			ExcludeFilters: FlowFilters{},
			End:            &expectedDate,
		},
		{
			Name:           "test003",
			FilePath:       "/var/log/network/flow-log/pa/test003.log",
			FieldMask:      FieldMask{"source", "destination", "verdict"},
			IncludeFilters: FlowFilters{},
			ExcludeFilters: FlowFilters{
				{
					DestinationPod: []string{"ingress/"},
				},
			},
			End: nil,
		},
	}

	for i := range expectedConfigs {
		assertFlowLogConfig(t, expectedConfigs[i], *config.FlowLogs[i])
	}
}

func TestInvalidConfigFile(t *testing.T) {

	invalidYamlFile := createInvalidYamlTestConfigFile(t)
	duplicatedNameYamlFile := createDuplicatedNameYamlTestConfigFile(t)
	duplicatedPathYamlFile := createDuplicatedPathYamlTestConfigFile(t)

	cases := []struct {
		name             string
		watcher          *configWatcher
		expectedErrorMsg string
	}{
		{
			name:             "missing file",
			watcher:          &configWatcher{configFilePath: "non-existing-file-name"},
			expectedErrorMsg: "cannot read file",
		},
		{
			name:             "invalid yaml",
			watcher:          &configWatcher{configFilePath: invalidYamlFile.Name()},
			expectedErrorMsg: "cannot parse yaml",
		},
		{
			name:             "duplicated name",
			watcher:          &configWatcher{configFilePath: duplicatedNameYamlFile.Name()},
			expectedErrorMsg: "invalid yaml config file duplicated flowlog name test001",
		},
		{
			name:             "duplicated path",
			watcher:          &configWatcher{configFilePath: duplicatedPathYamlFile.Name()},
			expectedErrorMsg: "invalid yaml config file duplicated flowlog path /var/log/network/flow-log/pa/test001.log",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, _, err := tc.watcher.readConfig()
			assert.Nil(t, config)
			assert.Contains(t, err.Error(), tc.expectedErrorMsg)
		})
	}
}

func TestReloadNotificationReceived(t *testing.T) {
	// given
	file := createTestConfigFile(t)

	configReceived := false

	// when
	reloadInterval = 1 * time.Millisecond
	sut := NewConfigWatcher(file.Name(), func(_ context.Context, _ uint64, config DynamicExportersConfig) {
		configReceived = true
	})
	defer sut.Stop()

	// then
	assert.Eventually(t, func() bool {
		return configReceived
	}, 1*time.Second, 1*time.Millisecond)

}

func createTestConfigFile(t *testing.T) *os.File {
	testFileContent := `
flowLogs:
- name: "test001"
  filePath: "/var/log/network/flow-log/pa/test001.log"
  fieldMask: []
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
- name: "test002"
  filePath: "/var/log/network/flow-log/pa/test002.log"
  fieldMask: ["source.namespace", "source.pod_name", "destination.namespace", "destination.pod_name", "verdict"]
  includeFilters:
  - source_pod: ["default/"]
    event_type:
    - type: 1
  - destination_pod: ["frontend/nginx-975996d4c-7hhgt"]
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
- name: "test003"
  filePath: "/var/log/network/flow-log/pa/test003.log"
  fieldMask: ["source", "destination","verdict"]
  includeFilters: []
  excludeFilters:
  - destination_pod: ["ingress/"]
`
	return createConfigFile(t, testFileContent)
}

func createInvalidYamlTestConfigFile(t *testing.T) *os.File {
	testFileContent := `
flowLogs:
- name: "test001"
  filePath: "/var/log/network/flow-log/pa/test001.log"
  fieldMask: "this", "is", "invalid"
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
`
	return createConfigFile(t, testFileContent)
}

func createDuplicatedNameYamlTestConfigFile(t *testing.T) *os.File {
	testFileContent := `
flowLogs:
- name: "test001"
  filePath: "/var/log/network/flow-log/pa/test001.log"
  fieldMask: []
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
- name: "test001"
  filePath: "/var/log/network/flow-log/pa/test002.log"
  fieldMask: []
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
`
	return createConfigFile(t, testFileContent)
}

func createDuplicatedPathYamlTestConfigFile(t *testing.T) *os.File {
	testFileContent := `
flowLogs:
- name: "test001"
  filePath: "/var/log/network/flow-log/pa/test001.log"
  fieldMask: []
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
- name: "test002"
  filePath: "/var/log/network/flow-log/pa/test001.log"
  fieldMask: []
  includeFilters: []
  excludeFilters: []
  end: "2023-10-09T23:59:59-07:00"
`
	return createConfigFile(t, testFileContent)
}

func createConfigFile(t *testing.T, content string) *os.File {
	file, err := os.CreateTemp(t.TempDir(), "config.yaml")
	if err != nil {
		t.Fatalf("failed creating test file %v", err)
	}

	if _, err := file.Write([]byte(content)); err != nil {
		t.Fatalf("failed creating test file %v", err)
	}
	return file
}

func assertFlowLogConfig(t *testing.T, expected, actual FlowLogConfig) {

	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.FilePath, actual.FilePath)
	assert.Equal(t, expected.FieldMask, actual.FieldMask)
	assert.Equal(t, len(expected.IncludeFilters), len(actual.IncludeFilters))
	for i := range expected.IncludeFilters {
		assert.Equal(t, expected.IncludeFilters[i].String(), actual.IncludeFilters[i].String())
	}
	assert.Equal(t, len(expected.ExcludeFilters), len(actual.ExcludeFilters))
	for i := range expected.ExcludeFilters {
		assert.Equal(t, expected.ExcludeFilters[i].String(), actual.ExcludeFilters[i].String())
	}
	if expected.End == nil {
		assert.Nil(t, actual.End)
	} else {
		assert.True(t, expected.End.Equal(*actual.End), "expected %s vs actual %s", expected.End.String(), actual.End.String())
	}

}
