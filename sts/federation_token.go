package sts

import (
	"encoding/xml"
	"fmt"
	"github.com/abdollar/goamz/aws"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
)

const debug = true

var timeNow = time.Now

type Sts struct {
	aws.Auth
	aws.Region
}

type xmlErrors struct {
	RequestId string  `xml:"RequestID"`
	Errors    []Error `xml:"Errors>Error"`
}

// Error contains pertinent information from the failed operation.
type Error struct {
	// HTTP status code (200, 403, ...)
	StatusCode int
	// AutoScaling error code ("UnsupportedOperation", ...)
	Code string
	// The human-oriented error message
	Message   string
	RequestId string `xml:"RequestID"`
}

func (err *Error) Error() string {
	if err.Code == "" {
		return err.Message
	}

	return fmt.Sprintf("%s (%s)", err.Message, err.Code)
}

// Factory for the Sts type
func NewSts(auth aws.Auth, region aws.Region) (*Sts, error) {
	return &Sts{
		Auth:   auth,
		Region: region,
	}, nil
}

func (sts *Sts) query(params map[string]string, resp interface{}) error {
	params["Version"] = "2011-06-15"
	params["Timestamp"] = timeNow().In(time.UTC).Format(time.RFC3339)
	endpoint, err := url.Parse(sts.Region.STSEndPoint)
	if err != nil {
		return err
	}
	sign(sts.Auth, "GET", endpoint.Path, params, endpoint.Host)
	endpoint.RawQuery = multimap(params).Encode()
	if debug {
		fmt.Println("get { %v } -> {\n", endpoint.String())
	}
	r, err := http.Get(endpoint.String())
	if err != nil {
		return err
	}
	defer r.Body.Close()

	if debug {
		dump, _ := httputil.DumpResponse(r, true)
		fmt.Println("response:\n")
		fmt.Println("%v\n}\n", string(dump))
	}
	if r.StatusCode != 200 {
		return buildError(r)
	}
	err = xml.NewDecoder(r.Body).Decode(resp)
	return err
}

func multimap(p map[string]string) url.Values {
	q := make(url.Values, len(p))
	for k, v := range p {
		q[k] = []string{v}
	}
	return q
}

func addParamsList(params map[string]string, label string, ids []string) {
	for i, id := range ids {
		params[label+"."+strconv.Itoa(i+1)] = id
	}
}

func buildError(r *http.Response) error {
	errors := xmlErrors{}
	xml.NewDecoder(r.Body).Decode(&errors)
	var err Error
	if len(errors.Errors) > 0 {
		err = errors.Errors[0]
	}
	err.RequestId = errors.RequestId
	err.StatusCode = r.StatusCode
	if err.Message == "" {
		err.Message = r.Status
	}
	return &err
}

// ----------------------------------------------------------------------------
// STS base types and related functions.

type Credentials struct {
	SessionToken    string `xml:"SessionToken"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	Expiration      string `xml:"Expiration"`
	AccessKeyId     string `xml:"AccessKeyId"`
}

type FederatedUser struct {
	Arn             string `xml:"Arn"`
	FederatedUserId string `xml:"FederatedUserId"`
}

// GetFederationTokenResp defines the basic response structure.
type GetFederationTokenResp struct {
	RequestId     string        `xml:"ResponseMetadata>RequestId"`
	Credentials   Credentials   `xml:"GetFederationTokenResult>Credentials"`
	FederatedUser FederatedUser `xml:"GetFederationTokenResult>FederatedUser"`
}

func (sts *Sts) GetFederationToken(durationSeconds int) (resp *GetFederationTokenResp, err error) {
	resp = &GetFederationTokenResp{}
	params := make(map[string]string)
	params["Action"] = "GetFederationToken"
	params["DurationSeconds"] = strconv.Itoa(durationSeconds)
	err = sts.query(params, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
