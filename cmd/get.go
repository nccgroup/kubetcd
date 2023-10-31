/*
Copyright 2017 The Kubernetes Authors.

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

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/nccgroup/kubetcd/pkg/encoding"
	"github.com/spf13/cobra"
)

var (
	getLong = `Get objects and their details in YAML format. Same usage as kubectl get. By now only corev1 resources are supported.`

	getExample = `kubetcd get pod <name> (-n <namespace>) or kubetcd get pods`
)

var getCmd = &cobra.Command{
	Use:     "get",
	Short:   "Get objects and their details in YAML format. Same usage as kubectl get. By now only corev1 resources are supported.",
	Long:    getLong,
	Example: getExample,
	//Args:    cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resource = args[0]
		numArgs := len(args)

		if numArgs == 1 {
			return etcdctlGetAll()
		} else {
			resourceName = args[1]
			return etcdctlGet()
		}

	},
}

type getOptions struct {
	//resource     string
	//resourceName string
	cacert    string
	cert      string
	key       string
	endpoint  string
	namespace string
	all       bool
}

var getoptions *getOptions = &getOptions{}
var resource, resourceName string

func init() {
	RootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&getoptions.endpoint, "endpoint", "", "127.0.0.1:2379", "Endopint. Default: 127.0.0.1:2379")
	getCmd.Flags().StringVarP(&getoptions.cacert, "cacert", "", "/etc/kubernetes/pki/etcd/ca.crt", "CA Certificate")
	getCmd.Flags().StringVarP(&getoptions.key, "key", "", "/etc/kubernetes/pki/etcd/server.key", "Key File")
	getCmd.Flags().StringVarP(&getoptions.cert, "cert", "", "/etc/kubernetes/pki/etcd/server.crt", "Server Certificate")
	getCmd.Flags().StringVarP(&getoptions.namespace, "namespace", "n", "default", "Namespace")
	getCmd.Flags().BoolVarP(&getoptions.all, "all", "A", false, "All namespaces")
}

func etcdctlGet() error {
	var path string
	if strings.Contains(resource, "namespace") {
		path = "/registry/namespaces/" + resourceName
	} else {
		path = "/registry/" + resource + "s/" + getoptions.namespace + "/" + resourceName
	}
	command := exec.Command("etcdctl",
		"--endpoints", getoptions.endpoint,
		"--cert", getoptions.cert,
		"--key", getoptions.key,
		"--cacert", getoptions.cacert,
		"get", path)
	command.Env = append(command.Env, "ETCDCTL_API=3")
	outputFile := "kubetcd.output"
	out, err := command.Output()
	if err != nil {
		return err
	}
	err = writeOutputToFile(outputFile, out)
	if err != nil {
		return err
	}
	//fmt.Printf("Output written to %s\n", outputFile)
	options.inputFilename = "kubetcd.output"
	encoding.IsGet = true
	validateAndRun()
	os.Remove("kubetcd.output")
	os.Remove("kubetcd.yaml")
	return nil
}

func etcdctlGetAll() error {
	var path string
	var orderEtcd int
	if strings.Contains(resource, "service") {
		path = "/registry/services/specs/" + getoptions.namespace
		orderEtcd = 5
	} else if strings.Contains(resource, "nodes") {
		path = "/registry/minions/"
		orderEtcd = 3
	} else if strings.Contains(resource, "namespaces") {
		path = "/registry/namespaces/"
		orderEtcd = 3
	} else {
		path = "/registry/" + resource + "/" + getoptions.namespace
		orderEtcd = 4
	}

	command := exec.Command("etcdctl",
		"--endpoints", getoptions.endpoint,
		"--cert", getoptions.cert,
		"--key", getoptions.key,
		"--cacert", getoptions.cacert,
		"get", path,
		"--prefix", "--keys-only")
	command.Env = append(command.Env, "ETCDCTL_API=3")
	out, err := command.Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		parts := strings.Split(line, "/")
		if len(parts) >= orderEtcd+1 {
			fifthPart := parts[orderEtcd]
			fmt.Println(fifthPart)
		}
	}
	return nil
}

func writeOutputToFile(file string, data []byte) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	if err != nil {
		return err
	}
	return nil
}
