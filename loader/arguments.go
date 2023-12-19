package loader

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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
	StatsStdOut   bool   `json:"statsstdout"`
	SSLCert       string `json:"sslcert"`
	SSLKey        string `json:"sslkey"`
	UseSSL        bool   `json:"usessl"`
	PyroScope     bool   `json:"pyroscope"`
	PyroScopeHost string `json:"pyroscopehost"`
	LogFile       string `json:"logfile"`
}

func ArgParse(arguments *Args) {

	// takes cli arguments or loads from json config file

	networkPtr := flag.String("network", "127.0.0.1", "network address to filter for")
	subnetPtr := flag.String("mask", "255.255.240.0", "subnet mask to use")
	continuousPtr := flag.Bool("continuous", false, "run continuously")
	buffersizePtr := flag.Int("buffersize", 2000, "number of events to buffer for calculations")
	statsperiodPtr := flag.Int("statsperiod", 5, "output stats every x seconds")
	polltimePtr := flag.Int64("pollingtime", 300, "duration in seconds to poll for")
	promportPtr := flag.String("promport", "1986", "port for prom exporter to listen on")
	debugPtr := flag.Bool("debug", false, "enabling debugging")
	statsoutputPtr := flag.Bool("statsoutput", false, "output stats updates to stdout")
	sslcertPtr := flag.String("sslcert", "", "path to SSL cert to use for prom exporter")
	sslkeyPtr := flag.String("sslkey", "", "path to SSL priv key to use for prom exporter")
	usesslPtr := flag.Bool("usessl", false, "set to use HTTP and not HTTPS for Prom exporter")
	pyroscopePtr := flag.Bool("pyroscope", false, "sent application metrics to remote pyroschope host")
	pyroscopeHostPtr := flag.String("pyroscopehost", "http://grafana.networks-util.ask4.net", "remote pyroscope host to uset")

	configPtr := flag.String("loadconfig", "none", "load json config file. defaults to lanrtt.json")

	flag.Parse()

	// check if SSL args needed for Prom. Exporter exist

	if *configPtr != "none" {
		log.Printf("loading JSON config: %s\n", *configPtr)
		LoadConfig(*configPtr, arguments)
	} else {
		if (*sslcertPtr == "" || *sslkeyPtr == "") && *usesslPtr {
			log.Printf("SSL options missing. cant start\n")
			os.Exit(1)
		}
		arguments.Network = *networkPtr
		arguments.Subnet = *subnetPtr
		arguments.RunContinuous = *continuousPtr
		arguments.BufferSize = *buffersizePtr
		arguments.StatsPeriod = *statsperiodPtr
		arguments.PollTime = *polltimePtr
		arguments.PromPort = *promportPtr
		arguments.Debug = *debugPtr
		arguments.StatsStdOut = *statsoutputPtr
		arguments.SSLCert = *sslcertPtr
		arguments.SSLKey = *sslkeyPtr
		arguments.UseSSL = *usesslPtr
		arguments.PyroScope = *pyroscopePtr
		arguments.PyroScopeHost = *pyroscopeHostPtr

		log.Printf("loading cli arguments:\n")
		log.Printf(" Network: %s\n Subnet Mask: %s\n Run Continuously: %v\n Buffer size: %v\n Stats Period: %v\n Polling Time: %v\n Prom Exporter Port: %v\n Display Debug Output: %v\n Display Stats Output: %v\n SSL Cert: %v\n SSL Key: %v\n Non SSL: %v\n",
			arguments.Network, arguments.Subnet, arguments.RunContinuous, arguments.BufferSize, arguments.StatsPeriod, arguments.PollTime, arguments.PromPort, arguments.Debug, arguments.StatsStdOut, arguments.SSLCert, arguments.SSLKey, arguments.UseSSL)

	}

	if arguments.PyroScope {

		log.Printf("sending application metrics to remote pyroscope host: %s", arguments.PyroScopeHost)
		StartPyroScope(arguments)

	}
}

func LoadConfig(configFile string, arguments *Args) {

	jsonFile, err := os.Open(configFile)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)

	}

	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteValue), &arguments)

}
