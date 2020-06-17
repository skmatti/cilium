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

package writer

import (
	"os"

	"github.com/cilium/lumberjack/v2"
)

// Writer is the interface to use the writer.
type Writer interface {
	Write(data []byte) (n int, err error)
	Close() error
}

// NewFileWriter creates a writer with log rotation. maxSize is the max size of each file.
// maxBackups is the maximum number of backup files to keep.
func NewFileWriter(logPath, logFile string, maxSize, maxBackups int) (Writer, error) {
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		os.MkdirAll(logPath, os.ModePerm)
	}

	filename := logPath + "/" + logFile
	// Just to check we have access to the file.
	fp, err := os.OpenFile(filename, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0755)
	if err != nil {
		return nil, err
	}
	fp.Close()
	return &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    maxSize, // megabytes
		MaxBackups: maxBackups,
		LocalTime:  true,
	}, nil
}
