package worker

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/wushilin/tlsproxy_go/logging"
	"github.com/wushilin/tlsproxy_go/tlsheader"
)

type Worker struct {
	BindHost     string
	BindPort     int
	TargetPort   int
	Uploaded     uint64
	Downloaded   uint64
	TotalHandled int64
	Active       int64
}

var ID_GEN uint64 = 0

func (v *Worker) Start(wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
	}()
	listener := fmt.Sprintf("%s:%d", v.BindHost, v.BindPort)
	server, err := net.Listen("tcp4", listener)
	if err != nil {
		ERROR("Failed to LISTEN to %s:%s", listener, err)
		os.Exit(1)
	}
	defer server.Close()
	INFO("Listening on %s -> SNIHost:%d", listener, v.TargetPort)
	for {
		connection, err := server.Accept()
		if err != nil {
			ERROR("Error accepting connection: %s ", err.Error())
			os.Exit(1)
		}
		var connection_id = atomic.AddUint64(&ID_GEN, 1)
		INFO("%d Accepted from %v to %v", connection_id, connection.RemoteAddr(), connection.LocalAddr())
		go v.processClient(connection, connection_id)
	}
}

func (v *Worker) processClient(connection net.Conn, conn_id uint64) {
	atomic.AddInt64(&v.Active, 1)
	start := time.Now()
	buffer := make([]byte, 4096)
	var uploaded uint64 = 0
	var downloaded uint64 = 0
	defer func() {
		connection.Close()
		INFO("%d Done. Uptime: %v Uploaded: %d bytes Downloaded: %d bytes", conn_id, time.Since(start), uploaded, downloaded)
		atomic.AddUint64(&v.Uploaded, uploaded)
		atomic.AddUint64(&v.Downloaded, downloaded)
		atomic.AddInt64(&v.Active, -1)
		atomic.AddInt64(&v.TotalHandled, 1)
	}()

	// client hello must be read in 30 seconds
	connection.SetReadDeadline(time.Now().Add(time.Second * 30))
	nread, err := connection.Read(buffer)
	if err != nil {
		ERROR("%d TLS ClientHello read error: %s", conn_id, err)
		return
	}
	for !tlsheader.PreCheck(buffer[:nread]) {
		new_nread, err := connection.Read(buffer[nread:])
		if err != nil {
			ERROR("%d Closed before TLSHeader is ready: %s", conn_id, err)
			return
		}
		nread += new_nread
		if nread >= len(buffer) {
			// buffer full
			break
		}
	}

	if !tlsheader.PreCheck(buffer[:nread]) {
		ERROR("%d PreCheck failed on full buffer. Skipping", conn_id)
		return
	}
	sniInfo, err := tlsheader.Parse(buffer[:nread])
	if err != nil {
		ERROR("%d TLS Header parse failed: %s", conn_id, err)
		return
	}

	connection.SetReadDeadline(time.Time{})
	dest, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", sniInfo.SNIHost, v.TargetPort), 10*time.Second)
	if err != nil {
		WARN("%d Client %v can't connect to host %s: %s", conn_id, connection.RemoteAddr(), sniInfo.SNIHost, err)
		return
	}
	INFO("%d Client %v connected to host %s via %s", conn_id, connection.RemoteAddr(), sniInfo.SNIHost, dest.LocalAddr())
	wg := &sync.WaitGroup{}
	wg.Add(2)
	dest.Write(buffer[:nread])
	atomic.AddUint64(&uploaded, uint64(nread))
	go pipe(conn_id, &uploaded, &downloaded, connection, dest, wg)
	wg.Wait()
}

func pipe(conn_id uint64, uploaded *uint64, downloaded *uint64, src net.Conn, dest net.Conn, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()
		written, _ := io.Copy(src, dest)
		atomic.AddUint64(downloaded, uint64(written))
		src.Close()
	}()
	go func() {
		defer wg.Done()
		written, _ := io.Copy(dest, src)
		atomic.AddUint64(uploaded, uint64(written))
		dest.Close()
	}()
}
