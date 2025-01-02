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

	"github.com/casbin/casbin/v2"
	"github.com/spf13/cobra"
)

type ResponseBody struct {
	Allow   bool     `json:"allow"`
	Explain []string `json:"explain"`
}

// enforceExCmd represents the enforceEx command.
var enforceExCmd = &cobra.Command{
	Use:   "enforceEx",
	Short: "Test if a 'subject' can access a 'object' with a given 'action' based on the policy",
	Long:  `Test if a 'subject' can access a 'object' with a given 'action' based on the policy`,
	Run: func(cmd *cobra.Command, args []string) {
		modelPath, _ := cmd.Flags().GetString("model")
		policyPath, _ := cmd.Flags().GetString("policy")

		e, err := casbin.NewEnforcer(modelPath, policyPath)
		if err != nil {
			panic(err)
		}

		params := make([]interface{}, len(args))
		for i, v := range args {
			params[i] = v
		}

		res, explain, err := e.EnforceEx(params...)
		if err != nil {
			cmd.PrintErrf("Error during enforcement: %v\n", err)
			return
		}

		response := ResponseBody{
			Allow:   res,
			Explain: explain,
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			cmd.PrintErrf("Error marshaling JSON: %v\n", err)
			return
		}

		cmd.Println(string(jsonResponse))
	},
}

// enforceCmd represents the enforce command.
var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Test if a 'subject' can access a 'object' with a given 'action' based on the policy",
	Long:  `Test if a 'subject' can access a 'object' with a given 'action' based on the policy`,
	Run: func(cmd *cobra.Command, args []string) {
		modelPath, _ := cmd.Flags().GetString("model")
		policyPath, _ := cmd.Flags().GetString("policy")

		e, err := casbin.NewEnforcer(modelPath, policyPath)
		if err != nil {
			panic(err)
		}

		params := make([]interface{}, len(args))
		for i, v := range args {
			params[i] = v
		}

		res, err := e.Enforce(params...)
		if err != nil {
			cmd.PrintErrf("Error during enforcement: %v\n", err)
			return
		}

		response := ResponseBody{
			Allow:   res,
			Explain: []string{},
		}

		jsonResponse, err := json.Marshal(response)
		if err != nil {
			cmd.PrintErrf("Error marshaling response: %v\n", err)
			return
		}

		cmd.Println(string(jsonResponse))
	},
}

func init() {
	rootCmd.AddCommand(enforceExCmd)
	rootCmd.AddCommand(enforceCmd)

	enforceExCmd.Flags().StringP("model", "m", "", "Path to the model file")
	_ = enforceExCmd.MarkFlagRequired("model")
	enforceExCmd.Flags().StringP("policy", "p", "", "Path to the policy file")
	_ = enforceExCmd.MarkFlagRequired("policy")

	enforceCmd.Flags().StringP("model", "m", "", "Path to the model file")
	_ = enforceCmd.MarkFlagRequired("model")
	enforceCmd.Flags().StringP("policy", "p", "", "Path to the policy file")
	_ = enforceCmd.MarkFlagRequired("policy")
}
