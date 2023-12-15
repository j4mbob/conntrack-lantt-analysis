package main

import (
	"conntrack-lanrtt-analysis/lanrtt/conntrack"
	"conntrack-lanrtt-analysis/lanrtt/loader"
)

func main() {

	args := loader.Startup()
	conntrack.Poller(args)

}
