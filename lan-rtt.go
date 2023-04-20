package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Flows struct {
	FlowID       string
	DeviceIP     string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
}

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

func PollConntrack(arguments *Args) {

	args := "-E -e UPDATES -o timestamp,id --buffer-size 1064960 -p tcp --orig-src " + arguments.Network + " --mask-src " + arguments.Subnet

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
		fmt.Printf("std out error")
		log.Fatal(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Printf("stderr error")
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("start error")
		log.Fatal(err)

	}

	EventParser(stdout, stderr, arguments)

	if err := cmd.Wait(); err != nil {
		fmt.Printf("wait error")
		log.Fatal(err)
	}
	fmt.Println("Polling finished")

}

func EventParser(stdout io.ReadCloser, stderr io.ReadCloser, arguments *Args) {

	var regex = regexp.MustCompile(`^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`)

	EventMap := make(map[string]map[string]interface{})
	DeviceFlows := map[string][]float64{}
	Flows := make([]Flows, 10)

	mux := &sync.Mutex{}

	go ParseFlows(&Flows, DeviceFlows, arguments, mux)

	scannerStdout := bufio.NewScanner(stdout)
	scannerStderr := bufio.NewScanner(stderr)

	go func() {
		for scannerStdout.Scan() {
			output := scannerStdout.Text()
			matches := regex.FindAllStringSubmatch(output, -1)

			for _, attr := range matches {
				combineTimeStamps := attr[1] + "." + attr[2]
				var timestamp float64
				if s, err := strconv.ParseFloat(combineTimeStamps, 64); err == nil {
					timestamp = s
				}

				// simple ring buffer to throw away oldest flow when we get to BufferSize
				if len(Flows) == arguments.BufferSize {
					mux.Lock()
					Flows = Flows[1:]
					mux.Unlock()

				}
				NewEvent(timestamp, attr[3], attr[4], attr[5], attr[6], attr[7], attr[8], attr[9], attr[10], attr[11], attr[12], EventMap, &Flows, DeviceFlows, arguments, mux)
			}
		}
	}()

	go func() {
		for scannerStderr.Scan() {
			output := scannerStderr.Text()
			fmt.Println(output)
		}
	}()

}

func NewEvent(timestamp float64, pkttype string, origSrc string, origDst string, origSport string, origDport string, replySrc string, replyDst string, replySport string, replyDsport string, flow_id string, EventMap map[string]map[string]interface{}, flows *[]Flows, DeviceFlows map[string][]float64, arguments *Args, mux *sync.Mutex) {

	if arguments.ConntrackStdOut {
		fmt.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flow_id)
	}

	var syn_timestamp float64
	var ack_timestamp float64
	var lanrtt float64

	if pkttype == "SYN_RECV" {

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

	} else {

		_, present := EventMap[flow_id]

		if present {

			if EventMap[flow_id]["origSrc"] == origSrc && EventMap[flow_id]["origDst"] == origDst && EventMap[flow_id]["origSport"] == origSport && EventMap[flow_id]["origDport"] == origDport && EventMap[flow_id]["replySrc"] == replySrc && EventMap[flow_id]["replyDst"] == replyDst && EventMap[flow_id]["replySport"] == replySport && EventMap[flow_id]["replyDsport"] == replyDsport {
				ack_timestamp = timestamp
				syn_timestamp = EventMap[flow_id]["timestamp"].(float64)

				lanrtt = CalculateFlowRtt(syn_timestamp, ack_timestamp)

				mux.Lock()
				*flows = append(*flows, Flows{FlowID: flow_id, DeviceIP: origSrc, SynTimestamp: syn_timestamp, AckTimestamp: ack_timestamp, LanRTT: lanrtt})
				mux.Unlock()
				for _, flow := range *flows {
					if flow.DeviceIP == origSrc {
						mux.Lock()
						DeviceFlows[origSrc] = append(DeviceFlows[origSrc], flow.LanRTT)
						mux.Unlock()
					}
				}

				// throw away matched event to avoid NewEventMap constantly growing with every new event
				delete(EventMap, flow_id)

			}
		}
	}
}

func ParseFlows(flows *[]Flows, DeviceFlows map[string][]float64, arguments *Args, mux *sync.Mutex) {

	promMean, promHisto, promAgMean, promAgHisto, promDeviceCount := PromExporter(arguments.PromPort, arguments.SSLCert, arguments.SSLKey, arguments.NoSSL)
	// generates averages every x seconds (defined by statsPeriod)
	for {
		time.Sleep(time.Duration(arguments.StatsPeriod) * time.Second)

		CalculateAverages(&flows, promMean, promHisto, arguments, mux)
		CalculateAggregateAverages(DeviceFlows, promAgMean, promAgHisto, promDeviceCount, arguments, mux)

		mux.Lock()
		for k := range DeviceFlows {
			delete(DeviceFlows, k)
		}
		mux.Unlock()

	}

}

func PromExporter(promPort string, sslCert string, sslKey string, noSSL bool) (prometheus.Gauge, prometheus.Histogram, prometheus.Gauge, prometheus.Histogram, prometheus.Gauge) {

	reg := prometheus.NewRegistry()

	promMeanEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_mean_value",
		Help: "lanRtt average value",
	})

	promAgMeanEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_aggregated_device_flows_mean_value",
		Help: "lanRtt aggregated device flows average value",
	})

	promDeviceCountEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_unique_device_flows_value",
		Help: "lanRtt unique device flow count value",
	})

	promHistoEndpoint := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lanRtt_flows_histo_value",
		Help:    "lanRtt flows histo values",
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	promAgHistoEndpoint := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lanRtt_aggregated_device_flows_histo_value",
		Help:    "lanRtt aggregatred device flows histo values",
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	reg.MustRegister(promMeanEndpoint)
	reg.MustRegister(promHistoEndpoint)
	reg.MustRegister(promAgMeanEndpoint)
	reg.MustRegister(promDeviceCountEndpoint)
	reg.MustRegister(promAgHistoEndpoint)

	go func(reg *prometheus.Registry) {
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		if noSSL {
			log.Fatal(http.ListenAndServe(":"+promPort, nil))

		} else {
			log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
		}
		log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
	}(reg)

	return promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promAgHistoEndpoint, promDeviceCountEndpoint

}

func CalculateFlowRtt(syn_timestamp float64, ack_timestamp float64) float64 {
	delayTime := (ack_timestamp - syn_timestamp) * 1000
	return delayTime
}

func CalculateAverages(flows **[]Flows, promMean prometheus.Gauge, promHisto prometheus.Histogram, arguments *Args, mux *sync.Mutex) {

	var delayTotal float64
	var mean float64
	var flowCount int

	mux.Lock()
	for _, flow := range **flows {
		delayTotal += flow.LanRTT
		promHisto.Observe(flow.LanRTT)
	}
	flowCount = len(**flows)
	mux.Unlock()

	mean = delayTotal / float64(flowCount)
	promMean.Set(mean)

	if arguments.StatsStdOut {

		fmt.Printf("\nAll Flows: [delayTotal: %f] [Flowcount: %d] [LAN Rtt: %f]\n", delayTotal, flowCount, mean)
	}
}

func CalculateAggregateAverages(DeviceFlows map[string][]float64, promAgMean prometheus.Gauge, promAgHisto prometheus.Histogram, promDeviceCount prometheus.Gauge, arguments *Args, mux *sync.Mutex) {
	var devicesCount int
	var devicesMean float64

	mux.Lock()
	for _, v := range DeviceFlows {
		devicesMean += CalculateMean(v)
		promAgHisto.Observe(CalculateMean(v))
	}

	devicesCount = len(DeviceFlows)
	promDeviceCount.Set(float64(devicesCount))

	AggregatedMean := devicesMean / float64(devicesCount)

	if arguments.StatsStdOut {
		fmt.Printf("Aggregated Per Device: [Total Device Count: %v] [Aggregated Mean LAN Rtt: %v]\n", devicesCount, AggregatedMean)
	}

	promAgMean.Set(AggregatedMean)
	mux.Unlock()

}

func CalculateMean(array []float64) float64 {
	var sum float64
	sum = 0

	for _, value := range array {
		sum += value
	}
	mean := sum / float64(len(array))

	return mean

}
