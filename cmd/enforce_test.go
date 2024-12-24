// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_enforceCmd(t *testing.T) {
	basicArgs := []string{"enforceEx", "-m", "../test/basic_model.conf", "-p", "../test/basic_policy.csv"}

	tests := []struct {
		args     []string
		expected map[string]interface{}
	}{
		{
			args: []string{"alice", "data1", "read"},
			expected: map[string]interface{}{
				"allow":   true,
				"explain": []interface{}{"alice", "data1", "read"},
			},
		},
		{
			args: []string{"alice", "data1", "write"},
			expected: map[string]interface{}{
				"allow":   false,
				"explain": []interface{}{},
			},
		},
		{
			args: []string{"alice", "data2", "read"},
			expected: map[string]interface{}{
				"allow":   false,
				"explain": []interface{}{},
			},
		},
		{
			args: []string{"alice", "data2", "write"},
			expected: map[string]interface{}{
				"allow":   false,
				"explain": []interface{}{},
			},
		},
		{
			args: []string{"bob", "data2", "write"},
			expected: map[string]interface{}{
				"allow":   true,
				"explain": []interface{}{"bob", "data2", "write"},
			},
		},
		{
			args: []string{"bob", "data2", "read"},
			expected: map[string]interface{}{
				"allow":   false,
				"explain": []interface{}{},
			},
		},
	}

	for _, tt := range tests {
		cmd := rootCmd
		output, err := executeCommand(cmd, append(basicArgs, tt.args...)...)
		require.NoError(t, err)

		var actual map[string]interface{}
		err = json.Unmarshal([]byte(output), &actual)
		require.NoError(t, err)

		require.Equal(t, tt.expected["allow"], actual["allow"])
		require.Equal(t, tt.expected["explain"], actual["explain"])
	}
}
