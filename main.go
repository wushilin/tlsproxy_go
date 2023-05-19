package main

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/wushilin/tlsproxy_go/logging"
	"github.com/wushilin/tlsproxy_go/worker"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join([]string(*i), ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var binding arrayFlags
var logLevel int

func main() {
	flag.Var(&binding, "b", "Binding in listen:listen_port:target_port format (e.g. 0.0.0.0:9092:19092)")
	flag.IntVar(&logLevel, "loglevel", 0, "Log level (0 for debug, higher is less)")
	flag.Parse()

	INFO().Msgf("Setting Log level to %d", logLevel)
	SetLoggingLevel(logLevel)
	var global_wg = new(sync.WaitGroup)
	var workers = make([]*worker.Worker, 0)
	for _, next := range binding {
		tokens := strings.Split(next, ":")
		token_size := len(tokens)
		bind_host := ""
		bind_port := 0
		target_port := 0
		if token_size < 2 {
			ERROR().Msgf("Invalid binding spec: [%s]", next)
			os.Exit(1)
			continue
		} else if token_size == 2 {
			bind_host = tokens[0]
			bind_port_a, err := strconv.Atoi(tokens[1])
			if err != nil {
				ERROR().Msgf("Invalid binding spec: [%s]", next)
				os.Exit(1)
				continue
			}
			bind_port = bind_port_a
			target_port = bind_port
		} else if token_size == 3 {
			bind_host = tokens[0]
			bind_port_a, err := strconv.Atoi(tokens[1])
			if err != nil {
				ERROR().Msgf("Invalid binding spec: [%s]", next)
				os.Exit(1)
				continue
			}
			bind_port = bind_port_a

			target_port_a, err := strconv.Atoi(tokens[2])
			if err != nil {
				ERROR().Msgf("Invalid int: %d", err)
				continue
			}
			target_port = target_port_a
		} else {
			ERROR().Msgf("Unknown binding: %s", next)
			continue
		}
		INFO().Msgf("Starting connector worker bind: [%s], port: %d target: %d", bind_host, bind_port, target_port)

		var worker = &worker.Worker{
			BindHost:   bind_host,
			BindPort:   bind_port,
			TargetPort: target_port,
			Downloaded: 0,
			Uploaded:   0,
		}
		global_wg.Add(1)
		go worker.Start(global_wg)
		workers = append(workers, worker)
	}
	go report(workers)
	global_wg.Wait()
}

func report(ws []*worker.Worker) {
	for {
		for _, next := range ws {
			INFO().Msgf(" *** STATUS for %s:%d->%d uploaded %d bytes; downloaded %d bytes; active requests %d; total requests %d",
				next.BindHost, next.BindPort, next.TargetPort,
				next.Uploaded, next.Downloaded, next.Active, next.TotalHandled)
		}
		time.Sleep(30 * time.Second)
	}
}
