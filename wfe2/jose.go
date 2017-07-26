package wfe2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/letsencrypt/boulder/core"
	berrors "github.com/letsencrypt/boulder/errors"
	"github.com/letsencrypt/boulder/features"
	"github.com/letsencrypt/boulder/probs"

	"gopkg.in/square/go-jose.v2"
)

func algorithmForKey(key *jose.JSONWebKey) (string, error) {
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		return string(jose.RS256), nil
	case *ecdsa.PublicKey:
		switch k.Params().Name {
		case "P-256":
			return string(jose.ES256), nil
		case "P-384":
			return string(jose.ES384), nil
		case "P-521":
			return string(jose.ES512), nil
		}
	}
	return "", signatureValidationError("no signature algorithms suitable for given key type")
}

const (
	noAlgorithmForKey     = "WFE.Errors.NoAlgorithmForKey"
	invalidJWSAlgorithm   = "WFE.Errors.InvalidJWSAlgorithm"
	invalidAlgorithmOnKey = "WFE.Errors.InvalidAlgorithmOnKey"
)

// Check that (1) there is a suitable algorithm for the provided key based on its
// Golang type, (2) the Algorithm field on the JWK is either absent, or matches
// that algorithm, and (3) the Algorithm field on the JWK is present and matches
// that algorithm. Precondition: parsedJws must have exactly one signature on
// it. Returns stat name to increment if err is non-nil.
func checkAlgorithm(key *jose.JSONWebKey, parsedJws *jose.JSONWebSignature) (string, error) {
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return noAlgorithmForKey, err
	}
	jwsAlgorithm := parsedJws.Signatures[0].Header.Algorithm
	if jwsAlgorithm != algorithm {
		return invalidJWSAlgorithm, signatureValidationError(fmt.Sprintf(
			"signature type '%s' in JWS header is not supported, expected one of RS256, ES256, ES384 or ES512",
			jwsAlgorithm,
		))
	}
	if key.Algorithm != "" && key.Algorithm != algorithm {
		return invalidAlgorithmOnKey, signatureValidationError(fmt.Sprintf(
			"algorithm '%s' on JWK is unacceptable",
			key.Algorithm,
		))
	}
	return "", nil
}

// jwsAuthType represents whether a given POST request is authenticated using
// a JWS with an embedded JWK (v1 ACME style, new-account, revoke-cert) or an
// embeded Key ID (v2 AMCE style) or an unsupported/unknown auth type.
type jwsAuthType int

const (
	unknownKey              = "No registration exists matching provided key"
	embeddedJWK jwsAuthType = iota
	embeddedKeyID
	invalidAuthType
)

// jwsAuthType examines a JWS' protected headers to determine if
// the request being authenticated by the JWS is identified using an embedded
// JWK or an embedded key ID. If no signatures are present, or mutually
// exclusive authentication types are specified at the same time a problem is
// returned.
func checkJWSAuthType(jws *jose.JSONWebSignature) (jwsAuthType, *probs.ProblemDetails) {
	// jwsAuthType is called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	// There must not be a Key ID *and* an embedded JWK
	if header.KeyID != "" && header.JSONWebKey != nil {
		return invalidAuthType, probs.Malformed(
			"jwk and kid header fields are mutually exclusive")
	} else if header.KeyID != "" {
		return embeddedKeyID, nil
	} else if header.JSONWebKey != nil {
		return embeddedJWK, nil
	}
	return invalidAuthType, nil
}

// enforceJWSAuthType checks a provided JWS has the provided auth type. If there
// is an error determining the auth type or if it is not the expected auth type
// then a problem is returned.
func (wfe *WebFrontEndImpl) enforceJWSAuthType(
	jws *jose.JSONWebSignature,
	expectedAuthType jwsAuthType) *probs.ProblemDetails {
	// Check the auth type for the provided JWS
	authType, prob := checkJWSAuthType(jws)
	if prob != nil {
		wfe.stats.Inc("Errors.InvalidJWSAuth", 1)
		return prob
	}
	// If the auth type isn't the one expected return a sensible problem based on
	// what was expected
	if authType != expectedAuthType {
		wfe.stats.Inc("Errors.WrongJWSAuthType", 1)
		switch expectedAuthType {
		case embeddedKeyID:
			return probs.Malformed("No Key ID in JWS header")
		case embeddedJWK:
			return probs.Malformed("No embedded JWK in JWS header")
		}
	}
	return nil
}

// parseJWS extracts a JSONWebSignature from an HTTP POST request's body. If
// there is an error reading the JWS or if it has too few or too many
// signatures, a problem is returned and the requestEvent is mutated to contain
// the error.
func (wfe *WebFrontEndImpl) parseJWS(
	request *http.Request,
	logEvent *requestEvent) (*jose.JSONWebSignature, string, *probs.ProblemDetails) {
	// Verify that the POST request has the expected headers
	prob := wfe.validPOSTRequest(request, logEvent)
	if prob != nil {
		return nil, "", prob
	}

	// Read the POST request body's bytes. validPOSTRequest has already checked
	// that the Body is non-nil
	bodyBytes, err := ioutil.ReadAll(request.Body)
	if err != nil {
		wfe.stats.Inc("Errors.UnableToReadRequestBody", 1)
		logEvent.AddError("unable to read request body")
		return nil, "", probs.ServerInternal("unable to read request body")
	}

	body := string(bodyBytes)
	// Attempt to parse the JWS from the POST body's bytes
	parsedJWS, err := jose.ParseSigned(body)
	if err != nil {
		wfe.stats.Inc("Errors.JWSParseError", 1)
		logEvent.AddError("Parse error reading JWS from POST body")
		return nil, "", probs.Malformed("Parse error reading JWS")
	}
	if len(parsedJWS.Signatures) > 1 {
		wfe.stats.Inc("Errors.TooManySignaturesInJWS", 1)
		logEvent.AddError("Too many signatures in POST body JWS")
		return nil, "", probs.Malformed("Too many signatures in POST body")
	}
	if len(parsedJWS.Signatures) == 0 {
		wfe.stats.Inc("Errors.NoSignaturesInJWS", 1)
		logEvent.AddError("POST JWS not signed")
		return nil, "", probs.Malformed("POST JWS not signed")
	}

	return parsedJWS, body, nil
}

// keyExtractor is a function that returns a JSONWebKey based on input from a
// user-provided JSONWebSignature, for instance by extracting it from the input,
// or by looking it up in a database based on the input. It may mutate the
// provided requestEvent to add errors or account information. If applicable, an
// associated account will be returned along with the key. If there is no
// account (e.g. because this is a new-account request with an embedded JWK then
// the returned account will be nil.
type keyExtractor func(
	context.Context,
	*http.Request,
	*requestEvent,
	*jose.JSONWebSignature) (*jose.JSONWebKey, *core.Registration, *probs.ProblemDetails)

// extractJWK is an implementation of a keyExtractor that extracts a JWK from
// the provided JWS. It always returns a nil account pointer because the key is
// extracted from the JWS and not from a database lookup for an account. The
// provided requestEvent is mutated to add errors as appropriate.
func (wfe *WebFrontEndImpl) extractJWK(
	_ context.Context,
	_ *http.Request,
	logEvent *requestEvent,
	jws *jose.JSONWebSignature) (*jose.JSONWebKey, *core.Registration, *probs.ProblemDetails) {

	// We expect the request to be using an embedded JWK auth type and to not
	// contain the mutually exclusive KeyID.
	prob := wfe.enforceJWSAuthType(jws, embeddedJWK)
	if prob != nil {
		logEvent.AddError("JWS auth type was not expected embeddedJWK auth")
		return nil, nil, prob
	}

	// keyExtractor's are called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	// We can be sure that JSONWebKey is != nil because we have already called
	// enforceJWSAuthType()
	key := header.JSONWebKey

	// If the key isn't considered valid by go-jose return a problem immediately
	if !key.Valid() {
		wfe.stats.Inc("Errors.InvalidJWK", 1)
		logEvent.AddError("JWK in request was invalid")
		return nil, nil, probs.Malformed("Invalid JWK in JWS header")
	}

	return key, nil, nil
}

// lookupJWK is an implementation of a keyExtractor that extracts a JWK from the
// database doing a lookup by the provided key ID. A pointer to the account with
// a matching key ID is returned along with the key. The provided logEvent is
// mutated to set the Requester and Contacts fields based on the retreived
// account information or to add errors as appropriate.
func (wfe *WebFrontEndImpl) lookupJWK(
	ctx context.Context,
	request *http.Request,
	logEvent *requestEvent,
	jws *jose.JSONWebSignature) (*jose.JSONWebKey, *core.Registration, *probs.ProblemDetails) {

	// We expect the request to be using an embedded Key ID auth type and to not
	// contain the mutually exclusive embedded JWK.
	prob := wfe.enforceJWSAuthType(jws, embeddedKeyID)
	if prob != nil {
		logEvent.AddError("JWS auth type was not expected embeddedKeyID auth")
		return nil, nil, prob
	}

	// keyExtractor's are called after parseJWS() which defends against the
	// incorrect number of signatures.
	header := jws.Signatures[0].Header
	accountURL := header.KeyID
	prefix := wfe.relativeEndpoint(request, regPath)
	accountIDStr := strings.TrimPrefix(accountURL, prefix)

	// Convert the account ID string to an int64 for use with the SA's
	// GetRegistration RPC
	accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
	if err != nil {
		wfe.stats.Inc("Errors.InvalidKeyID", 1)
		logEvent.AddError("JWS key ID was invalid int64")
		return nil, nil, probs.Malformed(fmt.Sprintf("Malformed account ID in KeyID header"))
	}

	// Try to find the account for this account ID
	account, err := wfe.SA.GetRegistration(ctx, accountID)
	// If there was an error and it isn't a "Not Found" error, return
	// a ServerInternal problem since this is unexpected.
	if err != nil && !berrors.Is(err, berrors.NotFound) {
		wfe.stats.Inc("Errors.UnableToGetAccountByID", 1)
		logEvent.AddError(fmt.Sprintf("Error calling SA.GetRegistration: %s", err.Error()))
		return nil, nil, probs.ServerInternal(fmt.Sprintf(
			"Error retreiving account %q", accountURL))
	} else if berrors.Is(err, berrors.NotFound) {
		// If the account isn't found, return a suitable problem
		wfe.stats.Inc("Errors.KeyIDNotFound", 1)
		logEvent.AddError(fmt.Sprintf("Account %q not found", accountURL))
		return nil, nil, probs.AccountDoesNotExist(fmt.Sprintf(
			"Account %q not found", accountURL))
	}

	// Verify the account is not deactivated
	if features.Enabled(features.AllowAccountDeactivation) && account.Status != core.StatusValid {
		wfe.stats.Inc("Errors.AccountIsNotValid", 1)
		logEvent.AddError(fmt.Sprintf("Account %q has status %q", accountURL, account.Status))
		return nil, nil, probs.Unauthorized(
			fmt.Sprintf("Account is not valid, has status %q", account.Status))
	}

	// Update the logEvent with the account information and return the JWK
	logEvent.Requester = account.ID
	logEvent.Contacts = account.Contact
	return account.Key, &account, nil
}

// validPOSTURL checks the JWS' URL header against the expected URL based on the
// HTTP request. This prevents a JWS intended for one endpoint to be replayed
// against a different endpoint. It mutates the provided logEvent to capture any
// errors.
func (wfe *WebFrontEndImpl) validPOSTURL(
	request *http.Request,
	jws *jose.JSONWebSignature,
	logEvent *requestEvent) *probs.ProblemDetails {
	// validPOSTURL is called after parseJWS() which defends against the incorrect
	// number of signatures.
	header := jws.Signatures[0].Header
	extraHeaders := header.ExtraHeaders
	// Check that there is at least one Extra Header
	if len(extraHeaders) == 0 {
		wfe.stats.Inc("Errors.MissingURLinJWS", 1)
		logEvent.AddError("JWS header parameter 'url' missing")
		return probs.Malformed("JWS header parameter 'url' required")
	}
	// Try to read a 'url' Extra Header as a string
	headerURL, ok := extraHeaders[jose.HeaderKey("url")].(string)
	if !ok || len(headerURL) == 0 {
		wfe.stats.Inc("Errors.MissingURLinJWS", 1)
		logEvent.AddError("JWS header parameter 'url' missing")
		return probs.Malformed("JWS header parameter 'url' required")
	}
	// Compute the URL we expect to be in the JWS based on the HTTP request
	expectedURL := url.URL{
		// TODO(@cpu): Figure out how to detect the correct scheme
		Scheme: "http",
		Host:   request.Host,
		Path:   request.RequestURI,
	}
	// Check that the URL we expect is the one that was found in the signed JWS
	// header
	if expectedURL.String() != headerURL {
		return probs.Malformed(fmt.Sprintf(
			"JWS header parameter 'url' incorrect. Expected %q got %q",
			expectedURL.String(), headerURL))
	}
	return nil
}

// TODO(@CPU) - Write a comment for this function
func (wfe *WebFrontEndImpl) verifyPOST(
	ctx context.Context,
	logEvent *requestEvent,
	request *http.Request,
	kx keyExtractor) ([]byte, *jose.JSONWebKey, *jose.JSONWebSignature, *core.Registration, *probs.ProblemDetails) {

	// Parse the JWS from the POST body
	jws, body, prob := wfe.parseJWS(request, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	// Extract the JWK and associated account (if applicable) using the provided
	// key extractor function
	pubKey, account, prob := kx(ctx, request, logEvent, jws)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	// Check that the public key and JWS algorithms match expected
	if statName, err := checkAlgorithm(pubKey, jws); err != nil {
		wfe.stats.Inc(statName, 1)
		logEvent.AddError("checkAlgorithm failed: %q", err.Error())
		return nil, nil, nil, nil, probs.Malformed(err.Error())
	}

	// If the key doesn't meet the GoodKey policy return a problem immediately
	// This is perhaps unneccesary when the kx was == wfe.lookupJWK since the
	// pubKey comes from our own vetted database but checking again won't hurt.
	if err := wfe.keyPolicy.GoodKey(pubKey.Key); err != nil {
		wfe.stats.Inc("Errors.JWKRejectedByGoodKey", 1)
		logEvent.AddError("JWK in request was rejected by GoodKey: %s", err.Error())
		return nil, nil, nil, nil, probs.Malformed(err.Error())
	}

	// Verify the JWS signature with the extracted public key.
	// NOTE: It might seem insecure for the WFE to be trusted to verify
	// client requests, i.e., that the verification should be done at the
	// RA.  However the WFE is the RA's only view of the outside world
	// *anyway*, so it could always lie about what key was used by faking
	// the signature itself.
	payload, err := jws.Verify(pubKey)
	// If the signature verification fails, then return an error immediately with
	// a small bit of context from the JWS body
	if err != nil {
		n := len(body)
		if n > 100 {
			n = 100
		}
		wfe.stats.Inc("Errors.JWSVerificationFailed", 1)
		logEvent.AddError("verification of JWS with the JWK failed: %v; body: %s", err, body[:n])
		return nil, nil, nil, nil, probs.Malformed("JWS verification error")
	}
	// Store the verified payload in the logEvent
	logEvent.Payload = string(payload)

	// Check that the JWS contains a correct Nonce header
	prob = wfe.validNonce(jws, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	// Check that the HTTP request URL matches the URL in the signed JWS
	prob = wfe.validPOSTURL(request, jws, logEvent)
	if prob != nil {
		return nil, nil, nil, nil, prob
	}

	return []byte(payload), pubKey, jws, account, nil
}
