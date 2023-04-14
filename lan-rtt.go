package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"

	//"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Flows struct {
	FlowID       string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
}

func main() {

	network, subnetMask, continuous, pollTime, statsPeriod, stdOutput := ArgParse()

	PollConntrack(network, subnetMask, continuous, pollTime, statsPeriod, stdOutput)

}

/*func PromExporter() {

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":1986", nil)

	// not defined yet

}*/

func PollConntrack(network string, subnetMask string, continuous bool, pollTime int64, statsPeriod int, stdOutput bool) {

	var regex = regexp.MustCompile(`^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`)
	args := "-E -e UPDATES -o timestamp,id -p tcp --orig-src " + network + " --mask-src " + subnetMask
	//args := "-E -e UPDATES -o timestamp,id -p tcp --orig-src 10.152.0.2 --mask-src 255.255.240.0"
	var ctx context.Context
	var cancel context.CancelFunc
	var cmd *exec.Cmd

	if !continuous {
		fmt.Printf("Running for %v..\n", pollTime)
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(pollTime)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, "conntrack", strings.Split(args, " ")...)
	} else if continuous {
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

	NewEventMap := make(map[string]map[string]interface{})
	Flows := make([]Flows, 10)

	scanner := bufio.NewScanner(stdout)

	go ParseFlows(&Flows, statsPeriod)

	for scanner.Scan() {
		output := scanner.Text()
		matches := regex.FindAllStringSubmatch(output, -1)

		for _, attr := range matches {
			combineTimeStamps := attr[1] + "." + attr[2]
			var timestamp float64
			if s, err := strconv.ParseFloat(combineTimeStamps, 64); err == nil {
				timestamp = s
			}
			if len(Flows) == 10 {
				x := Flows[0]
				Flows = Flows[1:]
				fmt.Println(x)

			}

			NewEvent(timestamp, attr[3], attr[4], attr[5], attr[6], attr[7], attr[8], attr[9], attr[10], attr[11], attr[12], NewEventMap, &Flows, stdOutput)
		}

	}

	fmt.Println(Flows)
	fmt.Println("Polling finished")
	//CalculateAverages(&Flows)

}

func ParseFlows(flows *[]Flows, statsPeriod int) {
	// generates averages every x seconds (defined by statsPeriod)
	for {
		time.Sleep(time.Duration(statsPeriod) * time.Second)
		CalculateAverages(&flows)
	}

}

func ArgParse() (string, string, bool, int64, int, bool) {

	networkPtr := flag.String("network", "127.0.0.1", "network address to filter for")
	subnetPtr := flag.String("mask", "255.255.240.0", "subnet mask to use")
	continuousPtr := flag.Bool("continuous", false, "run continuously")
	statsPeriodPtr := flag.Int("statsperiod", 5, "output stats every x seconds")
	pollTimePtr := flag.Int64("pollingtime", 300, "duration in seconds to poll for")
	outputPtr := flag.Bool("output", false, "output conntrack updates to stdout")

	flag.Parse()

	return *networkPtr, *subnetPtr, *continuousPtr, *pollTimePtr, *statsPeriodPtr, *outputPtr
}

func NewEvent(timestamp float64, pkttype string, origSrc string, origDst string, origSport string, origDport string, replySrc string, replyDst string, replySport string, replyDsport string, flow_id string, NewEventMap map[string]map[string]interface{}, flows *[]Flows, stdOutput bool) {

	if stdOutput {
		fmt.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flow_id)
	}

	_, present := NewEventMap[flow_id]

	var syn_timestamp float64
	var ack_timestamp float64
	var lanrtt float64

	if present {
		if NewEventMap[flow_id]["origSrc"] == origSrc && NewEventMap[flow_id]["origDst"] == origDst && NewEventMap[flow_id]["origSport"] == origSport && NewEventMap[flow_id]["origDport"] == origDport && NewEventMap[flow_id]["replySrc"] == replySrc && NewEventMap[flow_id]["replyDst"] == replyDst && NewEventMap[flow_id]["replySport"] == replySport && NewEventMap[flow_id]["replyDsport"] == replyDsport {
			// flow match found
			if pkttype == "SYN_RECV" {
				syn_timestamp = timestamp
				ack_timestamp = NewEventMap[flow_id]["timestamp"].(float64)
			} else if pkttype == "ESTABLISHED" {
				ack_timestamp = timestamp
				syn_timestamp = NewEventMap[flow_id]["timestamp"].(float64)
			}
			lanrtt = CalculateFlowRtt(syn_timestamp, ack_timestamp)

			*flows = append(*flows, Flows{FlowID: flow_id, SynTimestamp: syn_timestamp, AckTimestamp: ack_timestamp, LanRTT: lanrtt})
			fmt.Println("Number of flows: ", len(*flows))

			//}

		}
	} else {

		NewEventMap[flow_id] = make(map[string]interface{})
		NewEventMap[flow_id]["timestamp"] = timestamp
		NewEventMap[flow_id]["type"] = pkttype
		NewEventMap[flow_id]["origSrc"] = origSrc
		NewEventMap[flow_id]["origDst"] = origDst
		NewEventMap[flow_id]["origSport"] = origSport
		NewEventMap[flow_id]["origDport"] = origDport
		NewEventMap[flow_id]["replySrc"] = replySrc
		NewEventMap[flow_id]["replyDst"] = replyDst
		NewEventMap[flow_id]["replySport"] = replySport
		NewEventMap[flow_id]["replyDsport"] = replyDsport

	}

}

func CalculateFlowRtt(syn_timestamp float64, ack_timestamp float64) float64 {
	delayTime := (ack_timestamp - syn_timestamp) * 1000
	return delayTime
}

func CalculateAverages(flows **[]Flows) {

	var delayTotal float64
	var mean float64
	var flowCount int

	for _, flow := range **flows {
		delayTotal += flow.LanRTT
	}

	flowCount = len(**flows)

	mean = delayTotal / float64(flowCount)

	fmt.Printf("\ndelayTotal: %f", delayTotal)
	fmt.Printf("\nflowcount: %d", flowCount)
	fmt.Printf("\nlan-rtt: %f\n", mean)
}
