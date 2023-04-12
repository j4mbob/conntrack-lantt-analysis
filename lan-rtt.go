package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
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
	//cmd := exec.Command("sh", "-c", "conntrack -E -e UPDATES -o timackamp,id -p tcp --orig-src 10.152.13.232")

	network, subnetmask, daemon, pollTime, stdOutput := ArgParse()

	if daemon == true {
		fmt.Println("running as daemon")
	}

	var regex = regexp.MustCompile(`^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(pollTime)*time.Second)
	defer cancel()
	args := "-E -e UPDATES -o timestamp,id -p tcp --orig-src " + network + " --mask-src " + subnetmask
	//args := "-E -e UPDATES -o timestamp,id -p tcp --orig-src 10.152.0.2 --mask-src 255.255.240.0"
	cmd := exec.CommandContext(ctx, "conntrack", strings.Split(args, " ")...)
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

	for scanner.Scan() {
		output := scanner.Text()
		matches := regex.FindAllStringSubmatch(output, -1)

		for _, attr := range matches {
			combineTimeStamps := attr[1] + "." + attr[2]
			var timestamp float64
			if s, err := strconv.ParseFloat(combineTimeStamps, 64); err == nil {
				timestamp = s
			}

			NewEvent(timestamp, attr[3], attr[4], attr[5], attr[6], attr[7], attr[8], attr[9], attr[10], attr[11], attr[12], NewEventMap, &Flows, stdOutput)
		}

	}

	fmt.Println("Polling finished")
	CalculateAverages(&Flows)

}

func ArgParse() (string, string, bool, int64, bool) {

	networkPtr := flag.String("network", "127.0.0.1", "network address to filter for")
	subnetPtr := flag.String("mask", "255.255.240.0", "subnet mask to use")
	daemonPtr := flag.Bool("daemon", false, "run as daemon")
	pollTimePtr := flag.Int64("pollingtime", 600, "duration in seconds to poll for")
	outputPtr := flag.Bool("output", false, "output conntrack updates to stdout")

	flag.Parse()

	return *networkPtr, *subnetPtr, *daemonPtr, *pollTimePtr, *outputPtr
}

func NewEvent(timestamp float64, pkttype string, origSrc string, origDst string, origSport string, origDport string, replySrc string, replyDst string, replySport string, replyDsport string, flow_id string, NewEventMap map[string]map[string]interface{}, flows *[]Flows, stdOutput bool) {

	if stdOutput == true {
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

func CalculateAverages(flows *[]Flows) {

	var delayTotal float64
	var mean float64
	var flowCount int

	for _, flow := range *flows {
		delayTotal += flow.LanRTT
	}

	flowCount = len(*flows)

	mean = delayTotal / float64(flowCount)

	fmt.Printf("\ndelayTotal: %f", delayTotal)
	fmt.Printf("\nflowcount: %d", flowCount)
	fmt.Printf("\nlan-rtt: %f\n", mean)
}
