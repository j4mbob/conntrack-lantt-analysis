package loader

import (
	"os"
	"runtime"

	"github.com/grafana/pyroscope-go"
)

func Startup() *Args {

	arguments := new(Args)
	ArgParse(arguments)

	return arguments

}

func StartPyroScope(arguments *Args) {

	runtime.SetMutexProfileFraction(5)
	runtime.SetBlockProfileRate(5)

	pyroscope.Start(pyroscope.Config{
		ApplicationName: "lan-rtt-metrics", ServerAddress: arguments.PyroScopeHost + ":4040", Logger: nil,
		Tags: map[string]string{"hostname": os.Getenv("HOSTNAME"), "application": "lan-rtt-metrics"},
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileMutexCount,
			pyroscope.ProfileMutexDuration,
			pyroscope.ProfileBlockCount,
			pyroscope.ProfileBlockDuration,
		},
	})

}
