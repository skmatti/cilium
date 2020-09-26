// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policylogger

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v2"
)

// configFile is the configuration file name with path that stores customized configuration.
var configFile string = "/var/log/network/policy-logging.conf"

type PolicyLoggerConfiguration struct {
	LogFilePath            *string `yaml:"logFilePath"`
	LogFileName            *string `yaml:"logFileName"`
	LogFileMaxSize         *uint   `yaml:"logFileMaxSize"`
	LogFileMaxBackups      *uint   `yaml:"logFileMaxBackups"`
	MaxLogRate             *uint   `yaml:"maxLogRate"`
	LogQueueSize           *uint   `yaml:"logQueueSize"`
	DenyAggregationSeconds *uint   `yaml:"denyAggregationSeconds"`
	DenyAggregationMapSize *uint   `yaml:"denyAggregationMapSize"`
	LogNodeName            *bool   `yaml:"logNodeName"`
}

type policyLoggerConfig struct {
	// logFilePath is the path to put output log file.
	logFilePath string

	// logFileName is the name to put output log file.
	logFileName string

	// logFileMaxSize is the max file size in Megabytes for one log file.
	logFileMaxSize uint

	// logFileMaxBackups is the max number of backup files for log rotation.
	logFileMaxBackups uint

	// maxLogRate is the max number of logs generated per second.
	maxLogRate uint

	// logQueueSize is the queue size of policy action log processing queues.
	logQueueSize uint

	// denyAggregationSeconds is the deny log aggregation interval in seconds.
	denyAggregationSeconds uint

	// denyAggregationMapSize is the size of the cache map for deny aggregation.
	// It decides the maximum different entries allowed within denyAggregationSeconds.
	denyAggregationMapSize uint

	// logNodeName decides if node name should be logged in the log output.
	logNodeName bool
}

func (c *policyLoggerConfig) print() string {
	var str = []string{
		fmt.Sprintf("log-file-path: %s", c.logFilePath),
		fmt.Sprintf("log-file-name: %s", c.logFileName),
		fmt.Sprintf("file-max-size: %d", c.logFileMaxSize),
		fmt.Sprintf("file-max-backups: %d", c.logFileMaxBackups),
		fmt.Sprintf("max-log-rate: %d", c.maxLogRate),
		fmt.Sprintf("queue-size: %d", c.logQueueSize),
		fmt.Sprintf("deny-aggregation-seconds: %d", c.denyAggregationSeconds),
		fmt.Sprintf("deny-aggregation-map-size: %d", c.denyAggregationMapSize),
		fmt.Sprintf("log-node-name: %v", c.logNodeName),
	}
	return strings.Join(str, ", ")
}

// defaultConfig are the default values used internally for the logger. They can be override
// if configFile exists and the fields exist in the PolicyLoggerConfiguration.
var defaultConfig = policyLoggerConfig{
	logFilePath:            "/var/log/network",
	logFileName:            "policy_action.log",
	logFileMaxSize:         10, // MB
	logFileMaxBackups:      5,
	maxLogRate:             500, // logs per second
	logQueueSize:           2000,
	denyAggregationSeconds: 5, // seconds
	denyAggregationMapSize: 3000,
	logNodeName:            true,
}

// loadInternalConfig read configuration from file if it exist
// to override existing internal configurations.
// These configuration are mainly for internal usage.
func loadInternalConfig(file string) *policyLoggerConfig {
	cfg := defaultConfig

	if _, err := os.Stat(file); err != nil {
		log.Infof("File %s doesn't exist. Use default configuration instead.", configFile)
		return &cfg
	}

	var userConfig PolicyLoggerConfiguration
	if b, err := ioutil.ReadFile(file); err != nil {
		log.Errorf("Readfile(%s) failed: = %v", configFile, err)
		return &cfg
	} else {
		err = yaml.Unmarshal(b, &userConfig)
		if err != nil {
			log.Errorf("Fail to unmarshal user configuration: %s, err %v.", string(b), err)
			return &cfg
		}
	}
	if userConfig.LogFilePath != nil {
		cfg.logFilePath = *userConfig.LogFilePath
	}
	if userConfig.LogFileName != nil {
		cfg.logFileName = *userConfig.LogFileName
	}
	if userConfig.LogFileMaxSize != nil {
		cfg.logFileMaxSize = *userConfig.LogFileMaxSize
	}
	if userConfig.LogFileMaxBackups != nil {
		cfg.logFileMaxBackups = *userConfig.LogFileMaxBackups
	}
	if userConfig.MaxLogRate != nil {
		cfg.maxLogRate = *userConfig.MaxLogRate
	}
	if userConfig.LogQueueSize != nil {
		cfg.logQueueSize = *userConfig.LogQueueSize
	}
	if userConfig.DenyAggregationSeconds != nil {
		cfg.denyAggregationSeconds = *userConfig.DenyAggregationSeconds
	}
	if userConfig.DenyAggregationMapSize != nil {
		cfg.denyAggregationMapSize = *userConfig.DenyAggregationMapSize
	}
	if userConfig.LogNodeName != nil {
		cfg.logNodeName = *userConfig.LogNodeName
	}
	return &cfg
}
