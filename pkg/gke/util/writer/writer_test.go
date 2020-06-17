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

// +build !privileged_tests

package writer

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

// TestNewFileWriter creates a writer and verify the file contains
// the text that is written into it.
func TestNewFileWriter(t *testing.T) {
	logPath := "/tmp/test"
	logFile := "test.log"
	w, err := NewFileWriter(logPath, logFile, 1, 2)
	if err != nil {
		t.Errorf("NewFileWriter() = (_, %v), want (_, nil)", err)
	}
	defer w.Close()
	defer os.RemoveAll(logPath)

	b := []byte("Hello!")
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		t.Errorf("Write() = (%d, %v), want (nil, %d)", err, n, len(b))
	}
	existsWithContent(logPath+"/"+logFile, b, t)
}

//existsWithContent verifies the given file has the given content.
func existsWithContent(path string, content []byte, t *testing.T) {
	if _, err := os.Stat(path); err != nil {
		t.Errorf("Stat(%s) = (_, %v), wants (_, nil)", path, err)
	}

	b, err := ioutil.ReadFile(path)
	if err != nil || !reflect.DeepEqual(content, b) {
		t.Errorf("ReadFile(%s) = (%v, %v), wants (%v, nil)",
			path, string(b), err, string(content))
	}
}
