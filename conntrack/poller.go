package conntrack

import (
	"conntrack-lanrtt-analysis/exporter"
	"conntrack-lanrtt-analysis/loader"
	"context"
	"log"
	"os/exec"
	"strings"
	"time"
)

func Poller(arguments *loader.Args, promMetrics *exporter.PromMetrics) {

	args := "-E -e UPDATES -o timestamp,id --buffer-size 1064960 -p tcp --orig-src " + arguments.Network + " --mask-src " + arguments.Subnet

	var ctx context.Context
	var cancel context.CancelFunc
	var cmd *exec.Cmd

	if !arguments.RunContinuous {
		log.Printf("Running for %v..\n", arguments.PollTime)
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(arguments.PollTime)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "conntrack", strings.Split(args, " ")...)
	} else if arguments.RunContinuous {
		log.Printf("Running continuosly..\n")
		cmd = exec.Command("conntrack", strings.Split(args, " ")...)

	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("std out error")
		log.Fatal(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("stderr error")
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Printf("start error")
		log.Fatal(err)

	}

	EventParser(stdout, stderr, arguments, promMetrics)

	if err := cmd.Wait(); err != nil {
		log.Printf("wait error")
		log.Fatal(err)
	}
	log.Println("Polling finished")

}
