package main

import (
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/wushilin/tlsproxy_go/logging"
	"github.com/wushilin/tlsproxy_go/rule"
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
var ruleFile string
var self_ip string

func main() {
	flag.Var(&binding, "b", "Binding in listen:listen_port:target_port format (e.g. 0.0.0.0:9092:19092)")
	flag.StringVar(&ruleFile, "acl", "", "ACL file for evaluating if host should be allowed")
	flag.IntVar(&logLevel, "loglevel", 0, "Log level (0 for debug, higher is less)")
	flag.StringVar(&self_ip, "selfip", "", "Self IP address. If set, this will prevent self connection loop")
	flag.Parse()

	INFO("Starting")
	INFO("Setting Log level to %d", logLevel)
	var acl *rule.RuleSet = nil
	var err error = nil
	if ruleFile != "" {
		acl, err = rule.Parse(ruleFile)
		if err != nil {
			ERROR("Failed to parse rule file %s:%s", ruleFile, err)
			os.Exit(1)
		}
		INFO("Successfully loaded ACL rules from %s", ruleFile)
	} else {
		INFO("Not loading ACL rules. you can specify -acl `rules.json` to enable ACL checks")
	}
	SetLogLevel(logLevel)
	var global_wg = new(sync.WaitGroup)
	var workers = make([]*worker.Worker, 0)
	for _, next := range binding {
		tokens := strings.Split(next, ":")
		token_size := len(tokens)
		bind_host := ""
		bind_port := 0
		target_port := 0
		if token_size < 2 {
			ERROR("Invalid binding spec: [%s]", next)
			os.Exit(1)
			continue
		} else if token_size == 2 {
			bind_host = tokens[0]
			bind_port_a, err := strconv.Atoi(tokens[1])
			if err != nil {
				ERROR("Invalid binding spec: [%s]", next)
				os.Exit(1)
				continue
			}
			bind_port = bind_port_a
			target_port = bind_port
		} else if token_size == 3 {
			bind_host = tokens[0]
			bind_port_a, err := strconv.Atoi(tokens[1])
			if err != nil {
				ERROR("Invalid binding spec: [%s]", next)
				os.Exit(1)
				continue
			}
			bind_port = bind_port_a

			target_port_a, err := strconv.Atoi(tokens[2])
			if err != nil {
				ERROR("Invalid int: %d", err)
				continue
			}
			target_port = target_port_a
		} else {
			ERROR("Unknown binding: %s", next)
			continue
		}
		INFO("Starting connector worker bind: [%s], port: %d target: %d", bind_host, bind_port, target_port)

		self_ips := make(map[string]bool)
		if len(self_ip) > 0 {
			tokens := strings.Split(self_ip, ";")
			for _, next := range tokens {
				next = strings.TrimSpace(next)
				if next != "" {
					self_ips[next] = true
				}
			}
		}
		INFO("Self IPs: %v", self_ips)

		var worker = &worker.Worker{
			BindHost:    bind_host,
			BindPort:    bind_port,
			TargetPort:  target_port,
			Downloaded:  0,
			Uploaded:    0,
			Acl:         acl,
			SelfAddress: self_ips,
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
			INFO(" *** STATUS for %s:%d->%d uploaded %d bytes; downloaded %d bytes; active requests %d; total requests %d",
				next.BindHost, next.BindPort, next.TargetPort,
				next.Uploaded, next.Downloaded, next.Active, next.TotalHandled)
		}
		time.Sleep(30 * time.Second)
	}
}
