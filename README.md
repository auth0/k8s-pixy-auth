# auth0-k8s-auth-client
Transparently authenticate kubectl users using Auth0

As of Kubernetes v1.11 there is beta support for a [client-go credentials plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins). Using the support it is possible to use an Auth0 application to authenticate users and provide tokens with which a correctly configured Kubernetes cluster can authorize user actions.

## Installation
At this point in the project installation is manual. In the future this will be automated.
1. Pull down this repo with `git clone git@github.com:auth0/auth0-k8s-client-go-exec-plugin.git $GOPATH/src/github.com/auth0/cloning/auth0-k8s-client-go-exec-plugin`
2. Go to the repo location and install the needed deps: `$GOPATH/src/github.com/auth0/cloning/auth0-k8s-client-go-exec-plugin && go get .`
3. Build a binary with `go build -o ~/.kube/auth0-kubectl-auth`

## Configuration
Before you can get up and running you need to configure a couple of things.

### Auth0
1. Go to [https://manage.auth0.com/#/apis](https://manage.auth0.com/#/apis) and create an API. This will represent the Kubernetes API. For this example, name it `minikube` and give it an identifier somewhere along the URL for your cluster `http://minikube`. Leave the signing to be RS256.
2. Under the settings section of the newly created API scroll down to `Allow Offline Access` and make sure it's set to on. This allows for refresh tokens to be given out for API tokens.
3. Go to [https://manage.auth0.com/#/applications](https://manage.auth0.com/#/applications) and create an application. This will be the application that users login to when authenticating to interact with Kubernetes. Name it something like `minikube-login` and choose `Native` as the application type. This application type is used because the [Authorization Code Grant Flow with PKCE](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce) is used by this tool and that flow will only work when the application type is `Native`.
4. Under the settings section of the newly created Application, add `http://localhost:8080/callback` to the `Allowed Callback URLs` section. This tool will be listening for a short period of time at that location when the user authenticates so it can handle receiving the needed information from Auth0.
5. Note the client ID for later.
6. Go to [https://manage.auth0.com/#/extensions](https://manage.auth0.com/#/extensions) and find and install the `Auth0 Authorization Extension`. This will allow you to set up the groups and assign users to them.
7. For this example, create two groups: `cluster-view` and `cluster-admin`. Assign them to your users.
8. In the upper right hand corner, select your username and click `Configuration` and then scroll down to `Persistance`.
9. Make sure the `Groups` slider is set to yes so the users groups will be stored in their profile. Scroll up and click `Publish Rule` so the information is store in their profiles.
10. Open up [Auth0 Rules](https://manage.auth0.com/#/rules) and create a new empty rule.
11. Name the rule `add groups to token` and set the contents of the rule to:
```javascript
function (user, context, callback) {
  context.idToken['http://groups'] = user.app_metadata.authorization.groups;
  return callback(null, user, context);
}
```
12. Save the rule. This rule is what adds the group a user was added to via the Authorization Extension to their token.


### Kubernetes
Kubernetes needs to be configured to validate tokens sent to it and also pull group information so it can apply roles. The settings for this are configured on the API server: 
```bash
--authorization-mode=RBAC \
--oidc-issuer-url="https://joncarl.auth0.com/" \
--oidc-client-id=9WAjckTrfdYV6KY0HLR74u32X4Ta7d4H \
--oidc-username-claim=email \
--oidc-groups-claim=http://groups \
--oidc-groups-prefix=minikube-
```

- `authorization-mode` - this needs to be set to `RBAC` so that Kubernetes uses roles to provide authorization
- `oidc-issuer-url` - this should be the URL of your Auth0 domain
- `oidc-client-id` - the client ID from step 5 of the Auth0 configuration
- `oidc-username-claim` - the token claim that the username will be pulled from. this must be set to email
- `oidc-groups-claim` - the token claim that the users groups will be pulled from. This needs to start with `http://`
- `oidc-groups-prefix` - the prefix that Kubernetes will add to each role from the token before matching it to a role in Kubernetes


For minikube this can be configured as follows:
```bash
minikube start --extra-config=apiserver.authorization-mode=RBAC \
--extra-config=apiserver.oidc-issuer-url="https://joncarl.auth0.com/" \
--extra-config=apiserver.oidc-client-id=9WAjckTrfdYV6KY0HLR74u32X4Ta7d4H \
--extra-config=apiserver.oidc-username-claim=email \
--extra-config=apiserver.oidc-groups-claim=http://groups \
--extra-config=apiserver.oidc-groups-prefix=minikube-
```

The next step is to create roles. For this example we already have two groups: `cluster-admin` and `cluster-view`. To make these groups in Kubernetes, run the following:
- `kubectl create clusterrolebinding minikube-cluster-view --clusterrole=view --group=minikube-cluster-view`
- `kubectl create clusterrolebinding minikube-cluster-admin --clusterrole=cluster-admin --group=minikube-cluster-admin`
Note that we added `minikube-` to the beginning of the `--group`. As mentioned above, Kubernetes will automatically prepend `minikube-` to the group name from the token (`cluster-admin` becomes `minikube-cluster-admin`) and then matches that group against the groups already in Kubernetes.

### kubectl
Now that we have the Auth0 and Kubernetes pieces set up, lets setup kubectl.

If you're following along with minikube, when you started minikube it put credentials in your `/.kube/config` file. Open up that file and find those credentials. They will be under the `users` section and the name will be `minikube`. Save or comment our those credentials. They are your backup credentials that have full access to the cluster. In their place put the following: 
```yaml
- name: minikube
  user:
    exec:
      apiVersion: "client.authentication.k8s.io/v1beta1"
      command: "auth0-kubectl-auth"
      args:
        - "<YOUR_AUTH0_DOMAIN>"
        - "<YOUR_AUTH0_APP_CLIENT_SECRET>"
        - "<YOUR_AUTH0_API_ID"
```
which should look similar to:
```yaml
- name: minikube
  user:
    exec:
      apiVersion: "client.authentication.k8s.io/v1beta1"
      command: "auth0-kubectl-auth"
      args:
        - "joncarl.auth0.com"
        - "9WAjckTrfdYV6KY0HLR74u32X4Ta7d4H"
        - "http://minikube"
```

- `user.exec.command` is the pointing to the binary we built earlier
- `user.exec.args` are the different args passed into the binary 

You're all set! Run any kubectl command and it will open your browser for you to authenticate and then use that token to identify you when talking to Kubernetes. Your tokens are stored locally, so once you initially authenticate it will store a refresh token to get new credentials whenever your tokens expire. If you need to clear out saved tokens, simply remove the config file located at `~/.auth0-k8s-client-go-exec-plugin/config`.
