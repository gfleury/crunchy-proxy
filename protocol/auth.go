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

func CreatePasswordMessage(password string) []byte {
	message := NewMessageBuffer([]byte{})

	/* Set the message type */
	err := message.WriteByte(PasswordMessageMessageType)
	if err != nil {
		return nil
	}

	/* Initialize the message length to zero. */
	_, err = message.WriteInt32(0)
	if err != nil {
		return nil
	}

	/* Add the password to the message. */
	_, err = message.WriteString(password)
	if err != nil {
		return nil
	}

	/* Update the message length */
	message.ResetLength(PGMessageLengthOffset)

	return message.Bytes()
}
