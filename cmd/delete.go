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
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var (
	deleteLong = `Delete resource directly from etcd`

	deleteExample = `kubectd delete pod <name> (-n <namespace>)`
)

var delCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete resource directly from etcd",
	Long:    deleteLong,
	Example: deleteExample,
	RunE: func(cmd *cobra.Command, args []string) error {
		resourceDel = args[0]
		resourceNameDel = args[1]
		return etcdctlDel()
	},
}

type delOptions struct {
	cacert    string
	cert      string
	key       string
	endpoint  string
	namespace string
}

var deloptions *delOptions = &delOptions{}
var resourceDel, resourceNameDel string

func init() {
	RootCmd.AddCommand(delCmd)
	delCmd.Flags().StringVarP(&deloptions.endpoint, "endpoint", "", "127.0.0.1:2379", "Endopint. Default: 127.0.0.1:2379")
	delCmd.Flags().StringVarP(&deloptions.cacert, "cacert", "", "/etc/kubernetes/pki/etcd/ca.crt", "CA Certificate")
	delCmd.Flags().StringVarP(&deloptions.key, "key", "", "/etc/kubernetes/pki/etcd/server.key", "Key File")
	delCmd.Flags().StringVarP(&deloptions.cert, "cert", "", "/etc/kubernetes/pki/etcd/server.crt", "Server Certificate")
	delCmd.Flags().StringVarP(&deloptions.namespace, "namespace", "n", "default", "Namespace")
}

func etcdctlDel() error {
	var path string
	var etcdOptions string

	if strings.Contains(resourceDel, "service") {
		path = "/registry/services/specs/" + deloptions.namespace + "s/" + resourceNameDel
	} else if strings.Contains(resourceDel, "node") {
		path = "/registry/minions/" + resourceNameDel
	} else if strings.Contains(resourceDel, "namespace") {
		path = "/registry/namespaces/" + resourceNameDel
	} else if strings.Contains(resourceDel, "event") {
		path = "/registry/events/" + deloptions.namespace + "/" + resourceNameDel + "."
		etcdOptions = "--prefix=true"
		fmt.Println(path)
	} else {
		path = "/registry/" + resourceDel + "s/" + deloptions.namespace + "/" + resourceNameDel
	}

	command := exec.Command("etcdctl",
		"--endpoints", deloptions.endpoint,
		"--cert", deloptions.cert,
		"--key", deloptions.key,
		"--cacert", deloptions.cacert,
		"del", path, etcdOptions)
	command.Env = append(command.Env, "ETCDCTL_API=3")
	_, err := command.Output()
	if err != nil {
		return err
	}
	return nil
}
