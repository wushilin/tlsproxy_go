package worker

import (
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	. "github.com/wushilin/tlsproxy_go/logging"
	"github.com/wushilin/tlsproxy_go/rule"
	"github.com/wushilin/tlsproxy_go/tlsheader"
)

type Worker struct {
	BindHost         string
	BindPort         int
	TargetPort       int
	Uploaded         uint64
	Downloaded       uint64
	TotalHandled     int64
	Active           int64
	Acl              *rule.RuleSet
	SelfAddress      map[string]bool
	IdleCloseSeconds int
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

	if v.Acl != nil {
		if !v.Acl.CheckAccess(sniInfo.SNIHost) {
			INFO("%d Acl rejected access to %s", conn_id, sniInfo.SNIHost)
			return
		} else {
			INFO("%d Acl accepted access to %s", conn_id, sniInfo.SNIHost)
		}
	}

	ips := lookup_ips(sniInfo.SNIHost)
	if is_self_ip(ips, v.SelfAddress) {
		INFO("%d Declined self to self access. %s in %v", conn_id, v.SelfAddress, ips)
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
	wg.Add(3)
	dest.Write(buffer[:nread])
	atomic.AddUint64(&uploaded, uint64(nread))
	go pipe(conn_id, &uploaded, &downloaded, connection, dest, wg, v.IdleCloseSeconds)
	wg.Wait()
}

func lookup_ips(host string) []string {
	result := make([]string, 0)
	ips, err := net.LookupIP(host)
	if err != nil {
		return result
	}
	for _, ip := range ips {
		result = append(result, ip.String())
	}
	return result
}

func is_self_ip(ips []string, myaddr map[string]bool) bool {
	for _, next := range ips {
		yes_or_no, ok := myaddr[next]
		if ok && yes_or_no {
			return true
		}
	}
	return false
}
func pipe(conn_id uint64, uploaded *uint64, downloaded *uint64, src net.Conn, dest net.Conn, wg *sync.WaitGroup, idle_close_seconds int) {
	var last_activity = time.Now()
	var running = true
	go func() {
		// src to dest go routine!
		defer func() {
			wg.Done()
			running = false
		}()
		buffer := make([]byte, 4096)
		nread := 0
		nwritten := 0
		var err error
		for {
			nread, err = src.Read(buffer)
			if err != nil {
				break
			}
			nwritten, err = dest.Write(buffer[:nread])
			last_activity = time.Now()
			if err != nil {
				break
			}
			atomic.AddUint64(uploaded, uint64(nwritten))
		}
		src.Close()
		dest.Close()
	}()
	go func() {
		//Dest to src
		defer func() {
			wg.Done()
			running = false
		}()
		buffer := make([]byte, 4096)
		nread := 0
		nwritten := 0
		var err error
		for {
			nread, err = dest.Read(buffer)
			if err != nil {
				break
			}
			nwritten, err = src.Write(buffer[:nread])
			last_activity = time.Now()
			if err != nil {
				break
			}
			atomic.AddUint64(downloaded, uint64(nwritten))
		}
		src.Close()
		dest.Close()
	}()
	go func() {
		defer wg.Done()
		for running {
			if idle_close_seconds < 0 {
				return
			}
			if time.Since(last_activity) > time.Second*time.Duration(idle_close_seconds) {
				INFO("%d client timeout with no activity (%d seconds)", conn_id, idle_close_seconds)
				src.Close()
				dest.Close()
			}
		}
	}()
}
