// Code generated by go-swagger; DO NOT EDIT.

package health

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/aaishahhamdha/oathkeeper/internal/httpclient/models"
)

// IsInstanceAliveReader is a Reader for the IsInstanceAlive structure.
type IsInstanceAliveReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *IsInstanceAliveReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewIsInstanceAliveOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewIsInstanceAliveDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewIsInstanceAliveOK creates a IsInstanceAliveOK with default headers values
func NewIsInstanceAliveOK() *IsInstanceAliveOK {
	return &IsInstanceAliveOK{}
}

/*
IsInstanceAliveOK describes a response with status code 200, with default header values.

healthStatus
*/
type IsInstanceAliveOK struct {
	Payload *models.HealthStatus
}

// IsSuccess returns true when this is instance alive o k response has a 2xx status code
func (o *IsInstanceAliveOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this is instance alive o k response has a 3xx status code
func (o *IsInstanceAliveOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this is instance alive o k response has a 4xx status code
func (o *IsInstanceAliveOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this is instance alive o k response has a 5xx status code
func (o *IsInstanceAliveOK) IsServerError() bool {
	return false
}

// IsCode returns true when this is instance alive o k response a status code equal to that given
func (o *IsInstanceAliveOK) IsCode(code int) bool {
	return code == 200
}

func (o *IsInstanceAliveOK) Error() string {
	return fmt.Sprintf("[GET /health/alive][%d] isInstanceAliveOK  %+v", 200, o.Payload)
}

func (o *IsInstanceAliveOK) String() string {
	return fmt.Sprintf("[GET /health/alive][%d] isInstanceAliveOK  %+v", 200, o.Payload)
}

func (o *IsInstanceAliveOK) GetPayload() *models.HealthStatus {
	return o.Payload
}

func (o *IsInstanceAliveOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.HealthStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewIsInstanceAliveDefault creates a IsInstanceAliveDefault with default headers values
func NewIsInstanceAliveDefault(code int) *IsInstanceAliveDefault {
	return &IsInstanceAliveDefault{
		_statusCode: code,
	}
}

/*
IsInstanceAliveDefault describes a response with status code -1, with default header values.

unexpectedError
*/
type IsInstanceAliveDefault struct {
	_statusCode int

	Payload models.UnexpectedError
}

// Code gets the status code for the is instance alive default response
func (o *IsInstanceAliveDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this is instance alive default response has a 2xx status code
func (o *IsInstanceAliveDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this is instance alive default response has a 3xx status code
func (o *IsInstanceAliveDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this is instance alive default response has a 4xx status code
func (o *IsInstanceAliveDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this is instance alive default response has a 5xx status code
func (o *IsInstanceAliveDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this is instance alive default response a status code equal to that given
func (o *IsInstanceAliveDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *IsInstanceAliveDefault) Error() string {
	return fmt.Sprintf("[GET /health/alive][%d] isInstanceAlive default  %+v", o._statusCode, o.Payload)
}

func (o *IsInstanceAliveDefault) String() string {
	return fmt.Sprintf("[GET /health/alive][%d] isInstanceAlive default  %+v", o._statusCode, o.Payload)
}

func (o *IsInstanceAliveDefault) GetPayload() models.UnexpectedError {
	return o.Payload
}

func (o *IsInstanceAliveDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
