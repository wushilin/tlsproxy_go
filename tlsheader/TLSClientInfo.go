package tlsheader

type ClientHello struct {
	SNIHost string
}

type SNIError struct {
	Msg string
}

func (m *SNIError) Error() string {
	return m.Msg
}

// PreCheck if TLS Header is complete
func PreCheck(data []byte) bool {
	return data[0] == 0x16 && data[1] == 0x03 &&
		(data[2] > 0x00 && data[2] < 0x05) &&
		(int(data[3])*256+int(data[4]) == len(data)-5)
}

func skip(data []byte, count int) []byte {
	return data[count:]
}

func readLengthAndSkip(data []byte, numberOfBytes int) []byte {
	count := 1
	size := int(data[0])
	for count < numberOfBytes {
		size = size*256 + int(data[count])
		count++
	}
	var toSkip int = size + numberOfBytes
	return skip(data, toSkip)
}

func readExtension(clientHello []byte) (remaining []byte, extensionType int, data []byte) {
	byte0 := clientHello[0]
	byte1 := clientHello[1]
	byte2 := clientHello[2]
	byte3 := clientHello[3]
	extensionType = int(byte0)*256 + int(byte1)
	length := int(byte2)*256 + int(byte3)
	data = clientHello[4 : 4+length]
	remaining = clientHello[4+length:]
	return remaining, extensionType, data
}

func toInt(data []byte) int {
	count := 1
	size := int(data[0])
	for count < len(data) {
		size = size*256 + int(data[count])
		count++
	}
	return size
}

func Parse(clientHello []byte) (sniInfo ClientHello, err error) {
	defaultResult := ClientHello{SNIHost: ""}
	defer func() {
		if r := recover(); r != nil {
			sniInfo = defaultResult
			err = &SNIError{Msg: "bytes data boundary error"}
		}
	}()
	if clientHello[0] != 0x16 {
		return defaultResult, &SNIError{Msg: "Invalid initial byte. Expect 0x16"}
	}
	if clientHello[1] != 0x03 {
		return defaultResult, &SNIError{"Expect version byte 0x03"}
	}
	if clientHello[2] < 0x01 || clientHello[3] > 0x04 {
		return defaultResult, &SNIError{"Only support TLS 1.0 ~ 1.3 (outer)"}
	}

	dataLen := toInt(clientHello[3:5])
	if len(clientHello) < dataLen+5 {
		return defaultResult, &SNIError{Msg: "Data length mismatch(outer)"}
	}
	innerDataLen := toInt(clientHello[7:9])
	if len(clientHello) != innerDataLen+9 {
		return defaultResult, &SNIError{Msg: "Data length mismatch(inner)"}
	}

	innerVersionBytes := clientHello[9:11]
	if innerVersionBytes[0] != 0x03 {
		return defaultResult, &SNIError{"Expect version byte 0x03 (inner)"}
	}
	if innerVersionBytes[1] < 0x01 || innerVersionBytes[1] > 0x04 {
		return defaultResult, &SNIError{"Only support TLS 1.0 ~ 1.3 (inner)"}
	}
	clientHello = skip(clientHello, 43)
	// read the 31 random bytes
	clientHello = readLengthAndSkip(clientHello, 1)

	// read and skip cipher suites 00 62
	clientHello = readLengthAndSkip(clientHello, 2)

	// skip the compression extension
	clientHello = readLengthAndSkip(clientHello, 1)
	// skip remaining size identifier
	clientHello = skip(clientHello, 2)

	var sniData []byte = nil
	for len(clientHello) > 0 {
		extensionType := 0
		extensionData := []byte{}
		clientHello, extensionType, extensionData = readExtension(clientHello)
		if extensionType == 0 {
			sniData = extensionData
		}
	}
	if sniData != nil {
		byte0 := int(sniData[0])
		byte1 := int(sniData[1])
		size := int(byte0)*256 + byte1
		if len(sniData) != size+2 {
			return defaultResult, &SNIError{Msg: "Extension Size Mismatch"}
		}
		byte2 := int(sniData[2])
		byte3 := int(sniData[3])
		byte4 := int(sniData[4])
		if byte2 == 0 {
			strlen := byte3*256 + byte4
			if strlen == size-3 {
				host := string(sniData[5:])
				defaultResult.SNIHost = host
				return defaultResult, nil
			}
		}
	}
	return defaultResult, &SNIError{Msg: "Extension 0x00 0x00 not found"}
}
