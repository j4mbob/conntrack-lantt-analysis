package loader

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

type Args struct {
	Network       string `json:"network"`
	Subnet        string `json:"subnetmask"`
	RunContinuous bool   `json:"runcontinuous"`
	BufferSize    int    `json:"buffersize"`
	StatsPeriod   int    `json:"statsperiod"`
	PollTime      int64  `json:"pollingtime"`
	PromPort      string `json:"promport"`
	Debug         bool   `json:"debug"`
	StatsOut      bool   `json:"statsout"`
	SSLCert       string `json:"sslcert"`
	SSLKey        string `json:"sslkey"`
	UseSSL        bool   `json:"usessl"`
	PyroScope     bool   `json:"pyroscope"`
	PyroScopeHost string `json:"pyroscopehost"`
	PidFile       string `json:"pidfile"`
}

func ArgParse(arguments *Args) {

	// takes cli arguments or loads from json config file

	network := flag.String("network", "127.0.0.1", "network address to filter for")
	subnet := flag.String("mask", "255.255.240.0", "subnet mask to use")
	runContinuous := flag.Bool("continuous", false, "run continuously")
	bufferSize := flag.Int("buffersize", 2000, "number of events to buffer for calculations")
	statsPeriod := flag.Int("statsperiod", 5, "output stats every x seconds")
	pollTime := flag.Int64("pollingtime", 300, "duration in seconds to poll for")
	promPort := flag.String("promport", "1986", "port for prom exporter to listen on")
	debug := flag.Bool("debug", false, "enabling debugging")
	statsOut := flag.Bool("statsout", false, "output stats updates to stdout")
	sslCert := flag.String("sslcert", "", "path to SSL cert to use for prom exporter")
	sslKey := flag.String("sslkey", "", "path to SSL priv key to use for prom exporter")
	useSsl := flag.Bool("usessl", false, "set to use HTTP and not HTTPS for Prom exporter")
	pyroscope := flag.Bool("pyroscope", false, "sent application metrics to remote pyroschope host")
	pyroscopeHost := flag.String("pyroscopehost", "http://pyroscope-host:4040", "remote pyroscope host to uset")
	pidFile := flag.String("pdfile", "/run/lanrtt.pid", "pid file to use")

	config := flag.String("loadconfig", "none", "load json config file")

	flag.Parse()

	// check if SSL args needed for Prom. Exporter exist

	if *config != "none" {
		fmt.Printf("loading JSON config: %s\n", *config)
		LoadConfig(*config, arguments)
	} else {
		if (*sslCert == "" || *sslKey == "") && *useSsl {
			fmt.Printf("SSL options missing. Exiting\n")
			os.Exit(1)

		}
		arguments.Network = *network
		arguments.Subnet = *subnet
		arguments.RunContinuous = *runContinuous
		arguments.BufferSize = *bufferSize
		arguments.StatsPeriod = *statsPeriod
		arguments.PollTime = *pollTime
		arguments.PromPort = *promPort
		arguments.Debug = *debug
		arguments.StatsOut = *statsOut
		arguments.SSLCert = *sslCert
		arguments.SSLKey = *sslKey
		arguments.UseSSL = *useSsl
		arguments.PyroScope = *pyroscope
		arguments.PyroScopeHost = *pyroscopeHost
		arguments.PidFile = *pidFile

		fmt.Printf("loading cli arguments:\n")

	}

	if arguments.PyroScope {

		fmt.Printf("sending application metrics to remote pyroscope host: %s\n", arguments.PyroScopeHost)
		StartPyroScope(arguments)

	}
}

func LoadConfig(configFile string, arguments *Args) {

	jsonFile, err := os.Open(configFile)

	if err != nil {
		fmt.Println(err)
		CleanUp(arguments.PidFile)

	}

	defer jsonFile.Close()
	byteValue, _ := io.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &arguments)

}
