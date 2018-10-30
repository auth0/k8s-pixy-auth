# Auth0 -> k8s
Setup an Issuer via Auth0 to authenticate and authorize your k8s cluster

## Auth0 Setup
1. Go to [https://manage.auth0.com/#/apis](https://manage.auth0.com/#/apis) and create an API. This will represent the Kubernetes API. For this example, name it `minikube` and give it an identifier along the same lines `minikube`. Leave the signing to be RS256.
2. Under the settings section of the newly created API scroll down to `Allow Offline Access` and make sure it's set to on. This allows for refresh tokens to be given out for API tokens.
3. Go to [https://manage.auth0.com/#/applications](https://manage.auth0.com/#/applications) and create an application. This will be the application that users login to when authenticating to interact with Kubernetes. Name it something like `minikube-login` and choose `Native` as the application type. This application type is used because the [Authorization Code Grant Flow with PKCE](https://auth0.com/docs/api-auth/tutorials/authorization-code-grant-pkce) is used by this tool and that flow will only work when the application type is `Native`.
4. Under the settings section of the newly created Application, add `http://localhost:8080/callback` to the `Allowed Callback URLs` section. This tool will be listening for a short period of time at that location when the user authenticates so it can handle receiving the needed information from Auth0.
5. Note the client ID for later.
6. Go to [https://manage.auth0.com/#/extensions](https://manage.auth0.com/#/extensions) and find and install the `Auth0 Authorization Extension`. This will allow you to set up the groups and assign users to them.
7. For this example, create two groups: `cluster-view` and `cluster-admin`. Assign them to your users.
8. In the upper right hand corner, select your username and click `Configuration` and then scroll down to `Persistance`.
9. Make sure the `Groups` slider is set to yes so the users groups will be stored in their profile. Scroll up and click `Publish Rule` so the information is store in their profiles.
10. Open up [Auth0 Rules](https://manage.auth0.com/#/rules) and create a new empty rule.
11. Name the rule `add groups to token for minikube-login` and set the contents of the rule to:
```javascript
function (user, context, callback) {
  if (context.clientID === "<CLIENT ID>") {
    if (user.app_metadata !== undefined && 
        user.app_metadata.authorization !== undefined &&
        user.app_metadata.authorization.groups !== undefined) {
      context.idToken['http://groups'] = user.app_metadata.authorization.groups;
    }
  }
  return callback(null, user, context);
}
```
12. Make sure you've put in the client ID you saved from step 5 and save the rule. This rule is what adds the group a user was added to via the Authorization Extension to their token. We will only add these groups to their token when they are authenticating against your `minikube-login` application.


## Kubernetes Setup
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

The next step is to create groups. For this example we already have two groups on the Auth0 side: `cluster-admin` and `cluster-view`. To make these groups in Kubernetes, run the following:
- `kubectl create clusterrolebinding minikube-cluster-view --clusterrole=view --group=minikube-cluster-view`
- `kubectl create clusterrolebinding minikube-cluster-admin --clusterrole=cluster-admin --group=minikube-cluster-admin`
Note that we added `minikube-` to the beginning of the `--group`. As mentioned above, Kubernetes will automatically prepend `minikube-` to the group name from the token (`cluster-admin` becomes `minikube-cluster-admin`) and then matches that group against the groups already in Kubernetes.

## Kube Config Setup
Now that we have the Auth0 and Kubernetes pieces set up, lets setup your Kube config. k8s-pixy-auth makes it really easy to get things set up with one command. Run the following and make sure your add in the variables you need instead of the example ones: `k8s-pixy-auth init --context-name "minikube" --issuer-endpoint "https://joncarl.auth0.com" --audience "minikube" --client-id "QXV0aDAgaXMgaGlyaW5nISBhdXRoMC5jb20vY2FyZWVycyAK"`. If you want to see what happened in your kube config you should find that the context you passed into the init command has a new user aith `-exec-auth` on the end. If you find the user in the file is should be setup similar to the following:
```yaml
- name: minikube-exec-auth
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - auth
      - --issuer-endpoint=https://joncarl.auth0.com
      - --client-id=QXV0aDAgaXMgaGlyaW5nISBhdXRoMC5jb20vY2FyZWVycyAK
      - --audience=minikube
      command: /Users/joncarl/.k8s-pixy-auth/bin/k8s-pixy-auth
```

- `user.exec.command` is the pointing to the binary
- `user.exec.args` are the different args passed into the binary 

You're all set! Run any command against kubernetes and it will open your browser for you to authenticate and then use that token to identify you when talking to Kubernetes. Your tokens are stored locally, so once you initially authenticate it will store a refresh token to get new credentials whenever your tokens expire. If you need to clear out saved tokens, simply remove the config file located at `~/.k8s-pixy-auth/config`.