/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// JoinErrs returns an aggregated error based on the passed in slice of errors.
func JoinErrs(errs []error) error {
	var errStrs []string
	for _, e := range errs {
		errStrs = append(errStrs, e.Error())
	}
	return errors.New(strings.Join(errStrs, "; "))
}

// PrettyPrint returns json string representation of a struct.
// returns golang format if data cannot be marshalled.
func PrettyPrint(data interface{}) string {
	bytes, err := json.Marshal(data)
	if err != nil {
		// If input cannot be marshalled fallback to golang format.
		return fmt.Sprintf("%#v", data)
	}
	return string(bytes)
}
