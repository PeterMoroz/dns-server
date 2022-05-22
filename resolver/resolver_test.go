package dnsresolver

import "testing"
import "fmt"
import "encoding/binary"
import "bytes"

func TestValidRequestValidResponse(t *testing.T) {
	var request[512] byte = [512]byte {0x1d, 0xf1, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	
	copy(request[13:20], []byte("example"))
	copy(request[21:24], []byte("com"))
	
	r := resolver{request[0:512], false}
	response := r.Response()
	
	reqId := binary.BigEndian.Uint16(request[0:2])
	respId := binary.BigEndian.Uint16(response[0:2])
	
	if reqId != respId {
		msg := fmt.Sprintf("For response ID expected %04X got %04X", reqId, respId)
		t.Error(msg)
	}
		
	reqQdcount := binary.BigEndian.Uint16(request[4:6])
	respQdcount := binary.BigEndian.Uint16(response[4:6])
	
	if reqQdcount != respQdcount {
		msg := fmt.Sprintf("For qdcount expected %04X got %04X", reqQdcount, respQdcount)
		t.Error(msg)
	}
	
	ancount := binary.BigEndian.Uint16(response[6:8])
	if !(ancount >= 1) {
		msg := fmt.Sprintf("Expected ancount >= 1, got %d", ancount)
		t.Error(msg)	
	}
	
	if !bytes.Equal(request[12:25], response[12:25]) {
		t.Error("Mismatch of requested/replied names")
	}
}

func TestValidRequestNoRecordsResponse(t *testing.T) {
	var request[512] byte = [512]byte {0x1d, 0xf1, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	
	copy(request[13:20], []byte("example"))
	copy(request[21:24], []byte("org"))
	
	r := resolver{request[0:512], false}
	response := r.Response()
	
	reqId := binary.BigEndian.Uint16(request[0:2])
	respId := binary.BigEndian.Uint16(response[0:2])	
	
	if reqId != respId {
		msg := fmt.Sprintf("For response ID expected %04X got %04X", reqId, respId)
		t.Error(msg)
	}
	
	flags := binary.BigEndian.Uint16(response[2:4])
	var rcode uint8 = uint8(flags & 0xF)
	if rcode != 0x03 {
		msg := fmt.Sprintf("Expected rcode 3 (not found), got %d", rcode)
		t.Error(msg)
	}
	
	ancount := binary.BigEndian.Uint16(response[6:8])
	if ancount != 0 {
		msg := fmt.Sprintf("Expected ancount 0, got %d", ancount)
		t.Error(msg)	
	}

}