package main

import (
	"conntrack-lanrtt-analysis/conntrack"
	"os"

	"conntrack-lanrtt-analysis/loader"
)

func main() {

	args, promMetrics, pidFile := loader.Startup()
	conntrack.Poller(args, promMetrics)

	defer os.Remove(pidFile)

}
