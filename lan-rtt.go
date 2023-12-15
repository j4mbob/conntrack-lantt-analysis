package main

import (
	"conntrack-lanrtt-analysis/conntrack"

	"conntrack-lanrtt-analysis/loader"
)

func main() {

	args := loader.Startup()
	conntrack.Poller(args)

}
