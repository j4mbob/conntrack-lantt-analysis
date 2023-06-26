package main

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type Flows struct {
	FlowID       string
	DeviceIP     string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
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
