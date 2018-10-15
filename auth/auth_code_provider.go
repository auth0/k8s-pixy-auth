package auth

import "fmt"

type LocalhostCodeProvider struct {
	Issuer
	listener     AuthCallbackListener
	osInteractor OSInteractor
}

type AuthCodeResult struct {
	Code        string
	RedirectURI string
}

type CallbackResponse struct {
	Code  string
	Error error
}

type AuthCallbackListener interface {
	GetURL() string
	AwaitResponse(response chan CallbackResponse)
}

type OSInteractor interface {
	OpenURL(url string) error
}

func NewAuthCodeProvider(
	issuer Issuer,
	callbackListener AuthCallbackListener,
	osInteractor OSInteractor) *LocalhostCodeProvider {
	return &LocalhostCodeProvider{
		issuer,
		callbackListener,
		osInteractor,
	}
}

type AuthCodeRequest struct {
	Issuer   string
	ClientID string
	Audience string
	Response chan AuthCodeResult
}

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
		cp.listener.GetURL(),
	)); err != nil {
		return nil, err
	}

	callbackResult := <-codeReceiverCh

	if callbackResult.Error != nil {
		return nil, callbackResult.Error
	}

	return &AuthCodeResult{
		Code:        callbackResult.Code,
		RedirectURI: cp.listener.GetURL(),
	}, nil
}
