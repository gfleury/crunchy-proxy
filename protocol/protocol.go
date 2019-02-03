/*
Copyright 2017 Crunchy Data Solutions, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package protocol

import (
	"bytes"
	"encoding/binary"
)

/* PostgreSQL Protocol Version/Code constants */
const (
	ProtocolVersion int32 = 196608
	SSLRequestCode  int32 = 80877103

	/* SSL Responses */
	SSLAllowed    byte = 'S'
	SSLNotAllowed byte = 'N'
)

/* PostgreSQL Message Type constants. */
const (
	AuthenticationMessageType           byte = 'R' // Backend
	BackendKeyDataMessageType           byte = 'K' // Backend
	BindMessageType                     byte = 'B' // Frontend
	CancelRequestMessageType            byte = 'F' // Frontend
	CloseMessageType                    byte = 'C' // Frontend
	CloseCompleteMessageType            byte = '3' // Backend
	CommandCompleteMessageType          byte = 'C' // Backend
	CopyDataMessageType                 byte = 'd' // Backend/Frontend
	CopyDoneMessageType                 byte = 'c' // Backend/Frontend
	CopyFailMessageType                 byte = 'f' // Frontend
	CopyInResponseMessageType           byte = 'G' // Backend
	CopyOutResponseMessageType          byte = 'H' // Backend
	CopyBothResponseMessaType           byte = 'W' // Backend
	DataRowMessageType                  byte = 'D' // Backend
	DescribeMessageType                 byte = 'D' // Frontend
	EmptyQueryResponseMessageType       byte = 'I' // Backend
	ErrorResponseMessageType            byte = 'E' // Backend
	ExecuteMessageType                  byte = 'E' // Frontend
	FlushMessageType                    byte = 'H' // Frontend
	FunctionCallMessage                 byte = 'F' // Frontend
	FunctionCallResponseMessageType     byte = 'V' // Backend
	GSSResponseMessageType              byte = 'p' // Frontend
	NegotiateProtocolVersionMessageType byte = 'v' // Backend
	NoDataMessageType                   byte = 'n' // Backend
	NoticeResponseMessageType           byte = 'N' // Backend
	NotificationResponseMessageType     byte = 'A' // Backend
	ParameterDescriptionMessageType     byte = 't' // Backend
	ParameterStatusMessageType          byte = 'S' // Backend
	ParseMessageType                    byte = 'P' // Frontend
	ParseCompleteMessageType            byte = '1' // Backend
	PasswordMessageMessageType          byte = 'p' // Frontend
	PortalSuspendedMessageType          byte = 's' // Backend
	QueryMessageType                    byte = 'Q' // Frontend
	ReadyForQueryMessageType            byte = 'Z' // Backend
	RowDescriptionMessageType           byte = 'T' // Backend
	SASLInitialResponseMessageType      byte = 'p' // Frontend
	SASLResponseMessageType             byte = 'p' // Frontend
	SSLRequestMessageType               byte = '8' // Frontend
	SyncMessageType                     byte = 'S' // Frontend
	TerminateMessageType                byte = 'X' // Frontend
)

/*validFrontendMessageTypes PostgreSQL Valid Message Type byte array. */
var validFrontendMessageTypes = []byte{
	BindMessageType,
	CancelRequestMessageType,
	CloseMessageType,
	CopyDataMessageType,
	CopyDoneMessageType,
	CopyFailMessageType,
	DescribeMessageType,
	ExecuteMessageType,
	FlushMessageType,
	FunctionCallMessage,
	GSSResponseMessageType,
	ParseMessageType,
	PasswordMessageMessageType,
	QueryMessageType,
	SASLInitialResponseMessageType,
	SASLResponseMessageType,
	SSLRequestMessageType,
	SyncMessageType,
	TerminateMessageType,
}

/*validBackendMessageTypes PostgreSQL Valid Message Type byte array. */
var validBackendMessageTypes = []byte{
	AuthenticationMessageType,
	BackendKeyDataMessageType,
	CloseCompleteMessageType,
	CommandCompleteMessageType,
	CopyDataMessageType,
	CopyDoneMessageType,
	CopyInResponseMessageType,
	CopyOutResponseMessageType,
	CopyBothResponseMessaType,
	DataRowMessageType,
	EmptyQueryResponseMessageType,
	ErrorResponseMessageType,
	FunctionCallResponseMessageType,
	NegotiateProtocolVersionMessageType,
	NoDataMessageType,
	NoticeResponseMessageType,
	NotificationResponseMessageType,
	ParameterDescriptionMessageType,
	ParameterStatusMessageType,
	ParseCompleteMessageType,
	PortalSuspendedMessageType,
	ReadyForQueryMessageType,
	RowDescriptionMessageType,
}

/* PostgreSQL Authentication Method constants. */
const (
	AuthenticationOk          int32 = 0
	AuthenticationKerberosV5  int32 = 2
	AuthenticationClearText   int32 = 3
	AuthenticationMD5         int32 = 5
	AuthenticationSCM         int32 = 6
	AuthenticationGSS         int32 = 7
	AuthenticationGSSContinue int32 = 8
	AuthenticationSSPI        int32 = 9
)

func GetVersion(message []byte) (int32, error) {
	var code int32

	reader := bytes.NewReader(message[4:8])
	err := binary.Read(reader, binary.BigEndian, &code)
	return code, err
}

/*
 * Get the message type the provided message.
 *
 * message - the message
 */
func GetMessageType(message []byte) byte {
	return message[0]
}

/*
 * Get the message length of the provided message.
 *
 * message - the message
 */
func GetMessageLength(message []byte) (int32, error) {
	var messageLength int32

	reader := bytes.NewReader(message[1:5])
	err := binary.Read(reader, binary.BigEndian, &messageLength)

	return messageLength, err
}

/* IsAuthenticationOk
 *
 * Check an Authentication Message to determine if it is an AuthenticationOK
 * message.
 */
func IsAuthenticationOk(message []byte) bool {
	/*
	 * If the message type is not an Authentication message, then short circuit
	 * and return false.
	 */
	if GetMessageType(message) != AuthenticationMessageType {
		return false
	}

	var messageValue int32

	// Get the message length.
	messageLength, err := GetMessageLength(message)
	if err != nil {
		return false
	}

	// Get the message value.
	reader := bytes.NewReader(message[5:9])
	err = binary.Read(reader, binary.BigEndian, &messageValue)
	if err != nil {
		return false
	}

	return (messageLength == 8 && messageValue == AuthenticationOk)
}

func GetTerminateMessage() []byte {
	var buffer []byte
	buffer = append(buffer, 'X')

	//make msg len 1 for now
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, uint32(4))
	buffer = append(buffer, x...)
	return buffer
}

func ValidBackendMessage(t byte) bool {
	for _, tt := range validBackendMessageTypes {
		if t == tt {
			return true
		}
	}
	return false
}

func ValidFrontendMessage(t byte) bool {
	for _, tt := range validFrontendMessageTypes {
		if t == tt {
			return true
		}
	}
	return false
}

func ValidLongMessage(id byte) bool {
	return ((id) == 'T' || (id) == 'D' || (id) == 'd' || (id) == 'V' || (id) == 'E' || (id) == 'N' || (id) == 'A')
}
