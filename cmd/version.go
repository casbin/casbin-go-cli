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
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version       = "dev"
	CasbinVersion = "dev"
)

func init() {
	rootCmd.Flags().BoolP("version", "v", false, "Print version information")

	oldRun := rootCmd.Run
	rootCmd.Run = func(cmd *cobra.Command, args []string) {
		if v, _ := cmd.Flags().GetBool("version"); v {
			fmt.Printf("casbin-go-cli version: %s\n", Version)
			fmt.Printf("casbin version: %s\n", CasbinVersion)
			return
		}
		if oldRun != nil {
			oldRun(cmd, args)
		}
	}
}
