// Code generated by go-swagger; DO NOT EDIT.

package api

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/aaishahhamdha/oathkeeper/internal/httpclient/models"
)

// GetWellKnownJSONWebKeysReader is a Reader for the GetWellKnownJSONWebKeys structure.
type GetWellKnownJSONWebKeysReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetWellKnownJSONWebKeysReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetWellKnownJSONWebKeysOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetWellKnownJSONWebKeysInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetWellKnownJSONWebKeysOK creates a GetWellKnownJSONWebKeysOK with default headers values
func NewGetWellKnownJSONWebKeysOK() *GetWellKnownJSONWebKeysOK {
	return &GetWellKnownJSONWebKeysOK{}
}

/*
GetWellKnownJSONWebKeysOK describes a response with status code 200, with default header values.

jsonWebKeySet
*/
type GetWellKnownJSONWebKeysOK struct {
	Payload *models.JSONWebKeySet
}

// IsSuccess returns true when this get well known Json web keys o k response has a 2xx status code
func (o *GetWellKnownJSONWebKeysOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get well known Json web keys o k response has a 3xx status code
func (o *GetWellKnownJSONWebKeysOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get well known Json web keys o k response has a 4xx status code
func (o *GetWellKnownJSONWebKeysOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get well known Json web keys o k response has a 5xx status code
func (o *GetWellKnownJSONWebKeysOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get well known Json web keys o k response a status code equal to that given
func (o *GetWellKnownJSONWebKeysOK) IsCode(code int) bool {
	return code == 200
}

func (o *GetWellKnownJSONWebKeysOK) Error() string {
	return fmt.Sprintf("[GET /.well-known/jwks.json][%d] getWellKnownJsonWebKeysOK  %+v", 200, o.Payload)
}

func (o *GetWellKnownJSONWebKeysOK) String() string {
	return fmt.Sprintf("[GET /.well-known/jwks.json][%d] getWellKnownJsonWebKeysOK  %+v", 200, o.Payload)
}

func (o *GetWellKnownJSONWebKeysOK) GetPayload() *models.JSONWebKeySet {
	return o.Payload
}

func (o *GetWellKnownJSONWebKeysOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.JSONWebKeySet)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetWellKnownJSONWebKeysInternalServerError creates a GetWellKnownJSONWebKeysInternalServerError with default headers values
func NewGetWellKnownJSONWebKeysInternalServerError() *GetWellKnownJSONWebKeysInternalServerError {
	return &GetWellKnownJSONWebKeysInternalServerError{}
}

/*
GetWellKnownJSONWebKeysInternalServerError describes a response with status code 500, with default header values.

genericError
*/
type GetWellKnownJSONWebKeysInternalServerError struct {
	Payload *models.GenericError
}

// IsSuccess returns true when this get well known Json web keys internal server error response has a 2xx status code
func (o *GetWellKnownJSONWebKeysInternalServerError) IsSuccess() bool {
	return false
}

// IsRedirect returns true when this get well known Json web keys internal server error response has a 3xx status code
func (o *GetWellKnownJSONWebKeysInternalServerError) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get well known Json web keys internal server error response has a 4xx status code
func (o *GetWellKnownJSONWebKeysInternalServerError) IsClientError() bool {
	return false
}

// IsServerError returns true when this get well known Json web keys internal server error response has a 5xx status code
func (o *GetWellKnownJSONWebKeysInternalServerError) IsServerError() bool {
	return true
}

// IsCode returns true when this get well known Json web keys internal server error response a status code equal to that given
func (o *GetWellKnownJSONWebKeysInternalServerError) IsCode(code int) bool {
	return code == 500
}

func (o *GetWellKnownJSONWebKeysInternalServerError) Error() string {
	return fmt.Sprintf("[GET /.well-known/jwks.json][%d] getWellKnownJsonWebKeysInternalServerError  %+v", 500, o.Payload)
}

func (o *GetWellKnownJSONWebKeysInternalServerError) String() string {
	return fmt.Sprintf("[GET /.well-known/jwks.json][%d] getWellKnownJsonWebKeysInternalServerError  %+v", 500, o.Payload)
}

func (o *GetWellKnownJSONWebKeysInternalServerError) GetPayload() *models.GenericError {
	return o.Payload
}

func (o *GetWellKnownJSONWebKeysInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GenericError)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
