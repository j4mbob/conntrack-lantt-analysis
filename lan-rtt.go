package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Flows struct {
	FlowID       string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
}

type Args struct {
	Network       string `json:"network"`
	Subnet        string `json:"subnetmask"`
	RunContinuous bool   `json:"runcontinuous"`
	BufferSize    int    `json:"buffersize"`
	StatsPeriod   int    `json:"statsperiod"`
	PollTime      int64  `json:"pollingtime"`
	PromPort      string `json:"promport"`
	StdOut        bool   `json:"stdout"`
	SSLCert       string `json:"sslcert"`
	SSLKey        string `json:"sslkey"`
	NoSSL         bool   `json:"nossl"`
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
	outputPtr := flag.Bool("output", false, "output conntrack updates to stdout")
	sslcertPtr := flag.String("sslcert", "", "path to SSL cert to use for prom exporter")
	sslkeyPtr := flag.String("sslkey", "", "path to SSL priv key to use for prom exporter")
	nosslPtr := flag.Bool("nossl", false, "set to use HTTP and not HTTPS for Prom exporter")
	configPtr := flag.String("loadconfig", "none", "load json config file. defaults to lanrtt.json")

	flag.Parse()

	// check if SSL args needed for Prom. Exporter exist

	if *configPtr != "none" {
		fmt.Printf("loading json config")
		LoadConfig(*configPtr, arguments)
	} else {
		if (*sslcertPtr == "" || *sslkeyPtr == "") && *nosslPtr == false {
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
		arguments.StdOut = *outputPtr
		arguments.SSLCert = *sslcertPtr
		arguments.SSLKey = *sslkeyPtr
		arguments.NoSSL = *nosslPtr

		fmt.Printf("loading cli arguments:\n")
		fmt.Printf(" Network: %s\n Subnet Mask: %s\n Run Continuously: %v\n Buffer size: %v\n Stats Period: %v\n Polling Time: %v\n Prom Exporter Port: %v\n Display Output: %v\n SSL Cert: %v\n SSL Key: %v\n Non SSL: %v\n", arguments.Network, arguments.Subnet, arguments.RunContinuous, arguments.BufferSize, arguments.StatsPeriod, arguments.PollTime, arguments.PromPort, arguments.StdOut, arguments.SSLCert, arguments.SSLKey, arguments.NoSSL)

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

func PromExporter(promPort string, sslCert string, sslKey string, noSSL bool) (prometheus.Gauge, prometheus.Histogram) {

	reg := prometheus.NewRegistry()

	promMeanEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_mean_value",
		Help: "lanRtt average value",
	})

	promHistoEndpoint := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lanRtt_histo_value",
		Help:    "lanRtt Hiso values",
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	reg.MustRegister(promMeanEndpoint)
	reg.MustRegister(promHistoEndpoint)

	go func(reg *prometheus.Registry) {
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		if noSSL {
			log.Fatal(http.ListenAndServe(":"+promPort, nil))

		} else {
			log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
		}
		log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
	}(reg)

	return promMeanEndpoint, promHistoEndpoint

}

func PollConntrack(arguments *Args) {

	var regex = regexp.MustCompile(`^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`)
	args := "-E -e UPDATES -o timestamp,id -p tcp --orig-src " + arguments.Network + " --mask-src " + arguments.Subnet

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
		log.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Fatal(err)

	}

	EventMap := make(map[string]map[string]interface{})
	Flows := make([]Flows, 10)

	scanner := bufio.NewScanner(stdout)

	// launch thread for constant average calculations
	go ParseFlows(&Flows, arguments)

	for scanner.Scan() {
		output := scanner.Text()
		matches := regex.FindAllStringSubmatch(output, -1)

		for _, attr := range matches {
			combineTimeStamps := attr[1] + "." + attr[2]
			var timestamp float64
			if s, err := strconv.ParseFloat(combineTimeStamps, 64); err == nil {
				timestamp = s
			}

			// simple ring buffer queue for flow events
			if len(Flows) == arguments.BufferSize {
				Flows = Flows[1:]

			}

			NewEvent(timestamp, attr[3], attr[4], attr[5], attr[6], attr[7], attr[8], attr[9], attr[10], attr[11], attr[12], EventMap, &Flows, arguments)
		}

	}
	fmt.Println("Polling finished")

}

func ParseFlows(flows *[]Flows, arguments *Args) {

	promMean, promHisto := PromExporter(arguments.PromPort, arguments.SSLCert, arguments.SSLKey, arguments.NoSSL)
	// generates averages every x seconds (defined by statsPeriod)
	for {
		time.Sleep(time.Duration(arguments.StatsPeriod) * time.Second)
		CalculateAverages(&flows, promMean, promHisto, arguments)
	}

}

func NewEvent(timestamp float64, pkttype string, origSrc string, origDst string, origSport string, origDport string, replySrc string, replyDst string, replySport string, replyDsport string, flow_id string, EventMap map[string]map[string]interface{}, flows *[]Flows, arguments *Args) {

	if arguments.StdOut {
		fmt.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flow_id)
	}

	_, present := EventMap[flow_id]

	var syn_timestamp float64
	var ack_timestamp float64
	var lanrtt float64

	NewEventMap := make(map[string]interface{})
	NewEventMap["timestamp"] = timestamp
	NewEventMap["type"] = pkttype
	NewEventMap["origSrc"] = origSrc
	NewEventMap["origDst"] = origDst
	NewEventMap["origSport"] = origSport
	NewEventMap["origDport"] = origDport
	NewEventMap["replySrc"] = replySrc
	NewEventMap["replyDst"] = replyDst
	NewEventMap["replySport"] = replySport
	NewEventMap["replyDsport"] = replyDsport
	NewEventMap["flow_id"] = flow_id

	if present {
		if EventMap[flow_id]["origSrc"] == origSrc && EventMap[flow_id]["origDst"] == origDst && EventMap[flow_id]["origSport"] == origSport && EventMap[flow_id]["origDport"] == origDport && EventMap[flow_id]["replySrc"] == replySrc && EventMap[flow_id]["replyDst"] == replyDst && EventMap[flow_id]["replySport"] == replySport && EventMap[flow_id]["replyDsport"] == replyDsport {
			// flow match found with existing events
			if pkttype == "SYN_RECV" && EventMap[flow_id]["type"] == "ESTABLISHED" {

				syn_timestamp = timestamp
				ack_timestamp = EventMap[flow_id]["timestamp"].(float64)

			} else if pkttype == "ESTABLISHED" && EventMap[flow_id]["type"] == "SYN_RECV" {

				ack_timestamp = timestamp
				syn_timestamp = EventMap[flow_id]["timestamp"].(float64)

			} else if pkttype == "SYN_RECV" && EventMap[flow_id]["type"] == "SYN_RECV" {
				// matches on a TCP retry, replace EventMap entry with newest SYN_RECV packet
				EventMap[flow_id]["timestamp"] = timestamp
				EventMap[flow_id]["type"] = pkttype
				EventMap[flow_id]["origSrc"] = origSrc
				EventMap[flow_id]["origDst"] = origDst
				EventMap[flow_id]["origSport"] = origSport
				EventMap[flow_id]["origDport"] = origDport
				EventMap[flow_id]["replySrc"] = replySrc
				EventMap[flow_id]["replyDst"] = replyDst
				EventMap[flow_id]["replySport"] = replySport
				EventMap[flow_id]["replyDsport"] = replyDsport

			}

			lanrtt = CalculateFlowRtt(syn_timestamp, ack_timestamp)

			*flows = append(*flows, Flows{FlowID: flow_id, SynTimestamp: syn_timestamp, AckTimestamp: ack_timestamp, LanRTT: lanrtt})

			// throw away matched event to avoid NewEventMap constantly growing with every new event
			delete(EventMap, flow_id)

		}
	} else {

		EventMap[flow_id] = make(map[string]interface{})
		EventMap[flow_id]["timestamp"] = timestamp
		EventMap[flow_id]["type"] = pkttype
		EventMap[flow_id]["origSrc"] = origSrc
		EventMap[flow_id]["origDst"] = origDst
		EventMap[flow_id]["origSport"] = origSport
		EventMap[flow_id]["origDport"] = origDport
		EventMap[flow_id]["replySrc"] = replySrc
		EventMap[flow_id]["replyDst"] = replyDst
		EventMap[flow_id]["replySport"] = replySport
		EventMap[flow_id]["replyDsport"] = replyDsport

	}

}

func CalculateFlowRtt(syn_timestamp float64, ack_timestamp float64) float64 {
	delayTime := (ack_timestamp - syn_timestamp) * 1000
	return delayTime
}

func CalculateAverages(flows **[]Flows, promMean prometheus.Gauge, promHisto prometheus.Histogram, arguments *Args) {

	var delayTotal float64
	var mean float64
	var flowCount int

	for _, flow := range **flows {
		delayTotal += flow.LanRTT
		promHisto.Observe(flow.LanRTT)
	}

	flowCount = len(**flows)

	mean = delayTotal / float64(flowCount)
	promMean.Set(mean)
	promHisto.Observe(mean)

	//if arguments.StdOut {

	fmt.Printf("\ndelayTotal: %f", delayTotal)
	fmt.Printf("\nflowcount: %d", flowCount)
	fmt.Printf("\nlan-rtt: %f\n", mean)
	//}
}
