package main

import "os"
import "fmt"
import "net"
import "time"
import "encoding/binary"
import "strconv"
import "sync"
import "bytes"
import "math/rand"

type TCPHeader struct {
    SrcPort  uint16
    DstPort  uint16
    Seq      uint32
    Ack      uint32
    HdrSize  uint8
    Flags    uint8 // ignore NS flag
    Window   uint16
    Checksum uint16
    Urgent   uint16
    // no options
}

func (hdr TCPHeader) ToBytesAndCsum(src net.IP, dst net.IP) []byte {
    buf := make([]byte, 20)
    binary.BigEndian.PutUint16(buf, hdr.SrcPort)
    binary.BigEndian.PutUint16(buf[2:], hdr.DstPort)
    binary.BigEndian.PutUint32(buf[4:], hdr.Seq)
    binary.BigEndian.PutUint32(buf[8:], hdr.Ack)
    buf[12] = hdr.HdrSize << 4
    buf[13] = hdr.Flags
    binary.BigEndian.PutUint16(buf[14:], hdr.Window)
    binary.BigEndian.PutUint16(buf[16:], 0)
    binary.BigEndian.PutUint16(buf[18:], hdr.Urgent)

    pseudobuf := make([]byte, len(buf) + 12)
    copy(pseudobuf, src.To4())
    copy(pseudobuf[4:], dst.To4())
    pseudobuf[8] = 0
    pseudobuf[9] = 6
    pseudobuf[10] = byte(len(buf) >> 8)
    pseudobuf[11] = byte(len(buf) & 0x00ff)
    copy(pseudobuf[12:], buf)

    csum := checksum(pseudobuf, len(pseudobuf))
    binary.LittleEndian.PutUint16(buf[16:], csum) // don't know why

    return buf
}

func IPToLong(ip string) uint32 {
    var long uint32
    binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
    return long
}

func checksum(buf []byte, size int) uint16 {
    var sum uint32 = 0;

	/* Accumulate checksum */
    for i := int(0); i < size - 1; i += 2 {
        sum += uint32(binary.LittleEndian.Uint16(buf[i:i+2]))
	}

	/* Handle odd-sized case */
	if (size % 2 != 0) {
		sum += uint32(buf[len(buf)-1]);
	}

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)

	/* Invert to get the negative in ones-complement arithmetic */
	return uint16(^sum)
}

func ping(addr string) {

    conn, err := net.Dial("ip4:icmp", addr)
    buf := make([]byte, 8, 8)
    buf[0] = 8 // type
    buf[1] = 0 // code
    buf[2] = 0 // checksum 1
    buf[3] = 0 // checksum 2
    buf[4] = 0 // identifier 1
    buf[5] = 0 // identifier 2
    buf[6] = 0 // sequence number 1
    buf[7] = 0 // sequence number 2

    csum := checksum(buf, len(buf));
    buf[3] = byte(csum >> 8);
    buf[2] = byte(csum & 0x00ff);

    if err != nil {
        panic(err.Error())
    }

    for true {
        _, err = conn.Write(buf)
        if err != nil {
            panic(err.Error())
        }
        time.Sleep(1000000000)
    }
}

func doPingProbe(addr string) {
    all, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        panic(err.Error())
    }
    if err != nil {
        panic(err.Error())
    }
    go ping(addr)
    listen, err := net.ListenIP("ip4:icmp", all)
    if err != nil {
        panic(err.Error())
    }
    buf := make([]byte, 20, 20)
    for true {
        _, src, err := listen.ReadFromIP(buf)
        if err != nil {
            panic(err.Error())
        }
        if src.String() == addr {
            fmt.Println("Ping received");
        }
    }
}

func sendSyn(addr string, port uint16, wg *sync.WaitGroup) {
    defer wg.Done()
    srcport := uint16(rand.Intn(16383) + 49152)
    conn, err := net.Dial("ip4:tcp", addr)
    if err != nil {
        panic(err.Error())
    }
    /* buf := make([]byte, 20, 20)
    buf[1] = byte(srcport & 0x00ff)
    buf[0] = byte(srcport >> 8)
    buf[3] = byte(port & 0x00ff)
    buf[2] = byte(port >> 8)

    buf[4] = 200
    buf[5] = 100
    buf[6] = 200

    headsize := byte(5)
    buf[12] = headsize << 4
    buf[13] = 2

    buf[14] = 200 // window
    buf[15] = 0

    pseudobuf := make([]byte, 32, 32)

    csum := checksum(pseudobuf, 32)
    buf[16] = byte(csum & 0x00ff)
    buf[17] = byte(csum >> 8) */

    hdr := TCPHeader {
        SrcPort: srcport,
        DstPort: port,
        Seq: rand.Uint32(),
        Ack: 0,
        HdrSize: 5,
        Flags: 2,
        Window: 1000,
        Checksum: 0,
        Urgent: 0,
    }

    buf := hdr.ToBytesAndCsum(net.ParseIP("192.168.0.49"), net.ParseIP(addr))

    _, err = conn.Write(buf)
    if err != nil {
        panic(err.Error())
    }
}

func doSynScan(addr string, port string) {
    var wg sync.WaitGroup
    val, err := strconv.Atoi(port)
    if err != nil {
        panic(err.Error())
    }
    wg.Add(1)
    go sendSyn(addr, uint16(val), &wg)
    all, err := net.ResolveIPAddr("ip4", "0.0.0.0")
    if err != nil {
        panic(err.Error())
    }
    listen, err := net.ListenIP("ip4:tcp", all)
    if err != nil {
        panic(err.Error())
    }
    buf := make([]byte, 100, 100)
    for true {
        _, src, err := listen.ReadFromIP(buf)
        if err != nil {
            panic(err.Error())
        }
        if src.String() == addr {
            if buf[13] == 0x12 {
                fmt.Println("SYN/ACK")
            }
        }
    }
    wg.Wait()
}

func main() {
    rand.Seed(int64(time.Now().Nanosecond()))
    doSynScan(os.Args[1], os.Args[2])
}
