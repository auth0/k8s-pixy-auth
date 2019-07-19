If you have MacOS and want to test this out for Docker you can do the following:

1. Start up minikube like you would for testing the tool on MacOS and verify everything works for auth there.
2. Run `make build-linux` to get a linux executable.
3. Start up a Ubuntu docker image that maps the callback port, the code directy and any minikube cert locations: `docker run -it -p 8080:8080 -v $(pwd):/pixy -v /Users/grounded042/.minikube:/Users/grounded042/.minikube ubuntu`
4. Run `apt-get update && apt-get -y install curl nano` in the container.
5. Download and install the kubectl binary:
```
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
chmod +x ./kubectl
mv ./kubectl /usr/local/bin/kubectl
```
6. Setup the `~/.kube` directory: `mkdir ~/.kube`
7. Setup your kubeconfig file - you can copy the minikube parts from the kubeconfig file on MacOS:
```
nano ~/.kube/config
apiVersion: v1
clusters:
- cluster:
    certificate-authority: /Users/grounded042/.minikube/ca.crt
    server: https://192.168.99.100:8443
  name: minikube
contexts:
- context:
    cluster: minikube
    user: minikube
  name: minikube
current-context: minikube
kind: Config
preferences: {}
users:
- name: minikube
  user:
    client-certificate: /Users/grounded042/.minikube/client.crt
    client-key: /Users/grounded042/.minikube/client.key
```
8. Export the kubeconfig location: `export KUBECONFIG=/root/.kube/config`
9. Locate the linux binary: `cd /pixy/binaries/linux/`
10. Init the tool (putting in your own data): `./k8s-pixy-auth init --context-name "minikube" --issuer-endpoint "https://joncarl.auth0.com" --audience "minikube" --client-id "QXV0aDAgaXMgaGlyaW5nISBhdXRoMC5jb20vY2FyZWVycyAK"`
11. Run kubectl commands!