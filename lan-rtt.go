package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

type Args struct {
	Network         string `json:"network"`
	Subnet          string `json:"subnetmask"`
	RunContinuous   bool   `json:"runcontinuous"`
	BufferSize      int    `json:"buffersize"`
	StatsPeriod     int    `json:"statsperiod"`
	PollTime        int64  `json:"pollingtime"`
	PromPort        string `json:"promport"`
	ConntrackStdOut bool   `json:"conntrackstdout"`
	StatsStdOut     bool   `json:"statsstdout"`
	SSLCert         string `json:"sslcert"`
	SSLKey          string `json:"sslkey"`
	NoSSL           bool   `json:"nossl"`
}

func main() {

	arguments := new(Args)

	ArgParse(arguments)
	PollConntrack(arguments)

}

func ArgParse(arguments *Args) {

	// takes cli arguments or loads from json config file

	networkPtr := flag.String("network", "127.0.0.1", "network address to filter for")
	subnetPtr := flag.String("mask", "255.255.240.0", "subnet mask to use")
	continuousPtr := flag.Bool("continuous", false, "run continuously")
	buffersizePtr := flag.Int("buffersize", 1000, "number of events to buffer for calculations")
	statsperiodPtr := flag.Int("statsperiod", 5, "output stats every x seconds")
	polltimePtr := flag.Int64("pollingtime", 300, "duration in seconds to poll for")
	promportPtr := flag.String("promport", "1986", "port for prom exporter to listen on")
	conntrackoutputPtr := flag.Bool("conntrackoutput", false, "output conntrack updates to stdout")
	statsoutputPtr := flag.Bool("statsoutput", false, "output stats updates to stdout")
	sslcertPtr := flag.String("sslcert", "", "path to SSL cert to use for prom exporter")
	sslkeyPtr := flag.String("sslkey", "", "path to SSL priv key to use for prom exporter")
	nosslPtr := flag.Bool("nossl", false, "set to use HTTP and not HTTPS for Prom exporter")
	configPtr := flag.String("loadconfig", "none", "load json config file. defaults to lanrtt.json")

	flag.Parse()

	// check if SSL args needed for Prom. Exporter exist

	if *configPtr != "none" {
		fmt.Printf("loading JSON config: %s\n", *configPtr)
		LoadConfig(*configPtr, arguments)
	} else {
		if (*sslcertPtr == "" || *sslkeyPtr == "") && !*nosslPtr {
			fmt.Printf("SSL options missing. cant start\n")
			os.Exit(1)
		}
		arguments.Network = *networkPtr
		arguments.Subnet = *subnetPtr
		arguments.RunContinuous = *continuousPtr
		arguments.BufferSize = *buffersizePtr
		arguments.StatsPeriod = *statsperiodPtr
		arguments.PollTime = *polltimePtr
		arguments.PromPort = *promportPtr
		arguments.ConntrackStdOut = *conntrackoutputPtr
		arguments.StatsStdOut = *statsoutputPtr
		arguments.SSLCert = *sslcertPtr
		arguments.SSLKey = *sslkeyPtr
		arguments.NoSSL = *nosslPtr

		fmt.Printf("loading cli arguments:\n")
		fmt.Printf(" Network: %s\n Subnet Mask: %s\n Run Continuously: %v\n Buffer size: %v\n Stats Period: %v\n Polling Time: %v\n Prom Exporter Port: %v\n Display Conntrack Output: %v\n Display Stats Output: %v\n SSL Cert: %v\n SSL Key: %v\n Non SSL: %v\n", arguments.Network, arguments.Subnet, arguments.RunContinuous, arguments.BufferSize, arguments.StatsPeriod, arguments.PollTime, arguments.PromPort, arguments.ConntrackStdOut, arguments.StatsStdOut, arguments.SSLCert, arguments.SSLKey, arguments.NoSSL)

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
