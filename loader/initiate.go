package loader

import (
	"conntrack-lanrtt-analysis/exporter"

	"log"
	"os"
	"runtime"
	"strconv"
	"syscall"

	"github.com/grafana/pyroscope-go"
)

func Startup() (*Args, *exporter.PromMetrics, string) {

	const pidFile = "/run/lanrtt.pid"

	implementPID(pidFile)

	arguments := new(Args)
	ArgParse(arguments)

	exporterOpts := exporter.ExporterOpts{
		Port:    arguments.PromPort,
		UseSSL:  arguments.UseSSL,
		SSLCert: arguments.SSLCert,
		SSLKey:  arguments.SSLKey,
	}

	promReg := exporter.StartPromEndPoint(exporterOpts)
	promMetrics := exporter.BuildPromMetrics(promReg)

	return arguments, promMetrics, pidFile

}

func implementPID(pidFile string) {

	if checkPID(pidFile) {
		log.Fatalf("Another instance of the lanrtt is already running. Exiting.")
	}

	err := writePID(pidFile)
	if err != nil {
		log.Fatalf("Unable to write PID file: %s", err)
	}

}

func writePID(pidFile string) error {
	pid := []byte(strconv.Itoa(os.Getpid()) + "\n")
	return os.WriteFile(pidFile, pid, 0644)
}

func checkPID(pidFile string) bool {
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(string(pidData))
	if err != nil {
		log.Fatalf("Invalid PID in PID file: %s", pidData)
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
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
