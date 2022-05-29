package dns

import (
	"fmt"
	"encoding/binary"
)

type query struct {
	header
	qname string
	qtype uint16
	qclass uint16
}

func (q *query) decode(buf []byte) {
	q.header.decode(buf)
	
	var off byte = 12	// the length of the header
	q.qname = ""
	
	length := buf[off]
	for length != 0 {
		off += 1
		q.qname += string(buf[off:off+length])
		off += length
		length = buf[off]
		if length != 0 {
			q.qname += "."
		}
	}
	
	off += 1
	
	q.qtype = binary.BigEndian.Uint16(buf[off:])
	off += 2
	q.qclass = binary.BigEndian.Uint16(buf[off:])
}

func (q *query) toString() string {
	return fmt.Sprintf("DNS query { header: %s  qname: %s  qtype: %d  qclass: %d }", 
					q.header.toString(), q.qname, q.qtype, q.qclass)
}