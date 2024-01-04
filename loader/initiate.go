package loader

import (
	"conntrack-lanrtt-analysis/exporter"
	"os"
	"runtime"

	"github.com/grafana/pyroscope-go"
)

func Startup() (*Args, *exporter.PromMetrics) {

	arguments := new(Args)
	ArgParse(arguments)

	implementPID(arguments.PidFile)

	exporterOpts := exporter.ExporterOpts{
		Port:    arguments.PromPort,
		UseSSL:  arguments.UseSSL,
		SSLCert: arguments.SSLCert,
		SSLKey:  arguments.SSLKey,
	}

	promReg := exporter.StartPromEndPoint(exporterOpts)
	promMetrics := exporter.BuildPromMetrics(promReg)

	return arguments, promMetrics

}

func StartPyroScope(arguments *Args) {

	runtime.SetMutexProfileFraction(5)
	runtime.SetBlockProfileRate(5)

	pyroscope.Start(pyroscope.Config{
		ApplicationName: "lan-rtt-metrics", ServerAddress: arguments.PyroScopeHost, Logger: nil,
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
