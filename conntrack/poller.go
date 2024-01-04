package conntrack

import (
	"conntrack-lanrtt-analysis/exporter"
	"conntrack-lanrtt-analysis/loader"
	"context"
	"fmt"
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
		fmt.Printf("Running for %v..\n", arguments.PollTime)
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(arguments.PollTime)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "conntrack", strings.Split(args, " ")...)
	} else if arguments.RunContinuous {
		fmt.Printf("Running continuosly..\n")
		cmd = exec.Command("conntrack", strings.Split(args, " ")...)

	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Printf("std out error: %v\n", err)
		loader.CleanUp(arguments.PidFile)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("stderr error: %v\n", err)
		loader.CleanUp(arguments.PidFile)
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("start error: %v\n", err)
		loader.CleanUp(arguments.PidFile)

	}

	EventParser(stdout, stderr, arguments, promMetrics)

	if err := cmd.Wait(); err != nil {
		fmt.Printf("wait error: %v\n", err)
		loader.CleanUp(arguments.PidFile)
	}
	fmt.Printf("Polling finished\n")

}
