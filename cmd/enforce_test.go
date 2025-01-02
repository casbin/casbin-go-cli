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
	"testing"
)

func Test_enforceCmd(t *testing.T) {
	basicArgs := []string{"enforce", "-m", "../test/basic_model.conf", "-p", "../test/basic_policy.csv"}
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[]}\n", append(basicArgs, "alice", "data1", "read")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data1", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data2", "read")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data2", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[]}\n", append(basicArgs, "bob", "data2", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "bob", "data2", "read")...)

	domainArgs := []string{"enforce", "-m", "../test/rbac_with_domains_model.conf", "-p", "../test/rbac_with_domains_policy.csv"}
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[]}\n", append(domainArgs, "alice", "domain1", "data1", "read")...)
}

func Test_enforceExCmd(t *testing.T) {
	basicArgs := []string{"enforceEx", "-m", "../test/basic_model.conf", "-p", "../test/basic_policy.csv"}
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[\"alice\",\"data1\",\"read\"]}\n", append(basicArgs, "alice", "data1", "read")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data1", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data2", "read")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "alice", "data2", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[\"bob\",\"data2\",\"write\"]}\n", append(basicArgs, "bob", "data2", "write")...)
	assertExecuteCommand(t, rootCmd, "{\"allow\":false,\"explain\":[]}\n", append(basicArgs, "bob", "data2", "read")...)

	domainArgs := []string{"enforceEx", "-m", "../test/rbac_with_domains_model.conf", "-p", "../test/rbac_with_domains_policy.csv"}
	assertExecuteCommand(t, rootCmd, "{\"allow\":true,\"explain\":[\"admin\",\"domain1\",\"data1\",\"read\"]}\n", append(domainArgs, "alice", "domain1", "data1", "read")...)
}
