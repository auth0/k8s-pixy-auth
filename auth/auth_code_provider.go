package auth

import "fmt"

// LocalhostCodeProvider holds the information needed to easily get an
// authorization code
type LocalhostCodeProvider struct {
	Issuer
	listener     AuthCallbackListener
	osInteractor OSInteractor
}

// AuthCodeResult holds the needed code and redirect URI needed to exchange a
// authorization code for tokens
type AuthCodeResult struct {
	Code        string
	RedirectURI string
}

// CallbackResponse holds the code gotten from the authorization callback.
// Error will hold an error struct if an error occured.
type CallbackResponse struct {
	Code  string
	Error error
}

// AuthCallbackListener abstracts listening for the authorization callback
type AuthCallbackListener interface {
	GetCallbackURL() string
	AwaitResponse(response chan CallbackResponse)
	Close()
}

// OSInteractor abstracts opening a url on the users OS
type OSInteractor interface {
	OpenURL(url string) error
}

// NewALocalhostCodeProvider allows for the easy setup of LocalhostCodeProvider
func NewLocalhostCodeProvider(
	issuer Issuer,
	callbackListener AuthCallbackListener,
	osInteractor OSInteractor) *LocalhostCodeProvider {
	return &LocalhostCodeProvider{
		issuer,
		callbackListener,
		osInteractor,
	}
}

// GetCode opens a URL to authenticate and authorize a user and then returns
// the authrization code that is sent to the callback
func (cp *LocalhostCodeProvider) GetCode(challenge Challenge) (*AuthCodeResult, error) {
	codeReceiverCh := make(chan CallbackResponse)
	defer close(codeReceiverCh)
	go cp.listener.AwaitResponse(codeReceiverCh)

	if err := cp.osInteractor.OpenURL(fmt.Sprintf(
		"%s/authorize?audience=%s&scope=openid offline_access email&response_type=code&client_id=%s&code_challenge=%s&code_challenge_method=%s&redirect_uri=%s",
		cp.IssuerEndpoint,
		cp.Audience,
		cp.ClientID,
		challenge.Code,
		challenge.Method,
		cp.listener.GetCallbackURL(),
	)); err != nil {
		return nil, err
	}

	callbackResult := <-codeReceiverCh

	if callbackResult.Error != nil {
		return nil, callbackResult.Error
	}

	cp.listener.Close()
	return &AuthCodeResult{
		Code:        callbackResult.Code,
		RedirectURI: cp.listener.GetCallbackURL(),
	}, nil
}
