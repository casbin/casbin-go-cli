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
	"reflect"
	"regexp"
	"strconv"

	"github.com/casbin/casbin/v2"
	"github.com/spf13/cobra"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type ResponseBody struct {
	Allow   bool     `json:"allow"`
	Explain []string `json:"explain"`
}

// Function to handle enforcement results.
func handleEnforceResult(cmd *cobra.Command, res bool, explain []string, err error) {
	if err != nil {
		cmd.PrintErrf("Error during enforcement: %v\n", err)
		return
	}

	response := ResponseBody{
		Allow:   res,
		Explain: explain,
	}

	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetEscapeHTML(false)
	encoder.Encode(response)
}

// createStructWithValue creates a struct with a single field and value.
func createStructWithValue(fieldName string, value interface{}) interface{} {
	caser := cases.Title(language.English)
	structType := reflect.StructOf([]reflect.StructField{
		{
			Name: caser.String(fieldName),
			Type: reflect.TypeOf(value),
		},
	})

	structValue := reflect.New(structType).Elem()
	structValue.Field(0).Set(reflect.ValueOf(value))
	return structValue.Interface()
}

// Function to parse parameters and execute policy check.
func executeEnforce(cmd *cobra.Command, args []string, isEnforceEx bool) {
	modelPath, _ := cmd.Flags().GetString("model")
	policyPath, _ := cmd.Flags().GetString("policy")

	e, err := casbin.NewEnforcer(modelPath, policyPath)
	if err != nil {
		panic(err)
	}

	// Define regex pattern to match format like {field: value} or {field: "value"}.
	paramRegex := regexp.MustCompile(`{\s*"?(\w+)"?\s*:\s*(?:"?([^"{}]+)"?)\s*}`)

	params := make([]interface{}, len(args))
	for i, v := range args {
		// Using regex pattern to match parameters.
		if matches := paramRegex.FindStringSubmatch(v); len(matches) == 3 {
			fieldName := matches[1]
			valueStr := matches[2]

			// Try to convert value to integer first.
			if val, err := strconv.Atoi(valueStr); err == nil {
				params[i] = createStructWithValue(fieldName, val)
			} else {
				params[i] = createStructWithValue(fieldName, valueStr)
			}
			continue
		}
		params[i] = v
	}

	if isEnforceEx {
		res, explain, err := e.EnforceEx(params...)
		handleEnforceResult(cmd, res, explain, err)
	} else {
		res, err := e.Enforce(params...)
		handleEnforceResult(cmd, res, []string{}, err)
	}
}

// enforceCmd represents the enforce command.
var enforceCmd = &cobra.Command{
	Use:   "enforce",
	Short: "Test if a 'subject' can access a 'object' with a given 'action' based on the policy.",
	Long:  `Test if a 'subject' can access a 'object' with a given 'action' based on the policy.`,
	Run: func(cmd *cobra.Command, args []string) {
		executeEnforce(cmd, args, false)
	},
}

// enforceExCmd represents the enforceEx command.
var enforceExCmd = &cobra.Command{
	Use:   "enforceEx",
	Short: "Test if a 'subject' can access a 'object' with a given 'action' based on the policy.",
	Long:  `Test if a 'subject' can access a 'object' with a given 'action' based on the policy.`,
	Run: func(cmd *cobra.Command, args []string) {
		executeEnforce(cmd, args, true)
	},
}

func init() {
	rootCmd.AddCommand(enforceExCmd)
	rootCmd.AddCommand(enforceCmd)

	enforceExCmd.Flags().StringP("model", "m", "", "Path to the model file.")
	_ = enforceExCmd.MarkFlagRequired("model")
	enforceExCmd.Flags().StringP("policy", "p", "", "Path to the policy file.")
	_ = enforceExCmd.MarkFlagRequired("policy")

	enforceCmd.Flags().StringP("model", "m", "", "Path to the model file.")
	_ = enforceCmd.MarkFlagRequired("model")
	enforceCmd.Flags().StringP("policy", "p", "", "Path to the policy file.")
	_ = enforceCmd.MarkFlagRequired("policy")
}
