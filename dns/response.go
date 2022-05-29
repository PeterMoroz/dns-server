package dns

import (
	"fmt"
	"strings"
	"encoding/binary"
)

type response struct {
	header
	name string
	rtype uint16
	rclass uint16
	ttl uint32
	rdlength uint16
	rdata string
}

func (r *response) encode(buf []byte, n *int) {
	r.header.encode(buf)
	
	off := 12	// the length of the header
	
	// encode question section
	labels := strings.Split(r.name, ".")
	for _, lbl := range labels {		
		buf = append(buf, 0x00)
		buf[off] = byte(len(lbl))
		off += 1
		buf = append(buf, []byte(lbl)...)
		off += len(lbl)
	}
	
	buf = append(buf, 0x00)
	off += 1
	
	buf = append(buf, 0x00, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint16(buf[off:], r.rtype)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], r.rclass)
	off += 2
	
	// encode answer section
	for _, lbl := range labels {		
		buf = append(buf, 0x00)
		buf[off] = byte(len(lbl))
		off += 1
		buf = append(buf, []byte(lbl)...)
		off += len(lbl)
	}
	
	buf = append(buf, 0x00)
	off += 1	
	
	buf = append(buf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	binary.BigEndian.PutUint16(buf[off:], r.rtype)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], r.rclass)
	off += 2
	binary.BigEndian.PutUint32(buf[off:], r.ttl)
	off += 4
	binary.BigEndian.PutUint16(buf[off:], r.rdlength)	
	
	buf = append(buf, []byte(r.rdata)...)
	*n = off + 2 + int(r.rdlength)
}

func (r *response) toString() string {
	return fmt.Sprintf("DNS response { header: %s  name: %s  rtype: %d  rclass: %d  ttl: %d  rdlength: %d  rdata: %s }", 
						r.header.toString(), r.name, r.rtype, r.rclass, r.ttl, r.rdlength, r.rdata)
}