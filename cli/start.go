/*
Copyright 2017 Crunchy Data Solutions, Inc.
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

package cli

import (
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/crunchydata/crunchy-proxy/config"
	"github.com/crunchydata/crunchy-proxy/server"
	"github.com/crunchydata/crunchy-proxy/util/log"
)

var background bool
var configPath string
var logLevel string
var eventLoops string

var startCmd = &cobra.Command{
	Use:     "start",
	Short:   "start a proxy instance",
	Long:    "",
	Example: "",
	RunE:    runStart,
}

func init() {
	flags := startCmd.Flags()
	boolFlag(flags, &background, FlagBackground)
	stringFlag(flags, &configPath, FlagConfigPath)
	stringFlag(flags, &logLevel, FlagLogLevel)
	stringFlag(flags, &eventLoops, FlagEventLoops)
}

func runStart(cmd *cobra.Command, args []string) error {
	if background {
		newArgs := make([]string, 0, len(os.Args))

		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "--background") {
				continue
			}
			newArgs = append(newArgs, arg)
		}

		cmd := exec.Command(newArgs[0], newArgs[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		return cmd.Start()
	}

	log.SetLevel(logLevel)

	if configPath != "" {
		config.SetConfigPath(configPath)
	}

	config.ReadConfig()

	el, err := strconv.Atoi(eventLoops)
	if err != nil {
		log.Fatalf("Unable to parse event-loops, should be an number")
	}
	s := server.NewServer(el)

	s.Start()

	return nil
}
