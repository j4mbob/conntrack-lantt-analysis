package conntrack

import (
	"bufio"
	"conntrack-lanrtt-analysis/lanrtt/exporter"
	"conntrack-lanrtt-analysis/lanrtt/loader"
	"conntrack-lanrtt-analysis/lanrtt/metrics"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"sync"
	"time"
)

func EventParser(stdout io.ReadCloser, stderr io.ReadCloser, arguments *loader.Args) {
	regex := compileEventRegex()

	eventMap := make(map[string]map[string]interface{})
	deviceFlows := make(map[string][]float64)
	flows := make([]metrics.Flow, 0, 10)
	mux := &sync.Mutex{}

	go parseFlows(&flows, deviceFlows, arguments, mux)
	processStreams(stdout, stderr, regex, eventMap, &flows, deviceFlows, arguments, mux)
}

func compileEventRegex() *regexp.Regexp {
	pattern := `^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`
	return regexp.MustCompile(pattern)
}

func processStreams(stdout, stderr io.ReadCloser, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	go processStdout(stdout, regex, eventMap, flows, deviceFlows, arguments, mux)
	go processStderr(stderr)
}

func processStdout(stdout io.ReadCloser, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		output := scanner.Text()
		handleOutput(output, regex, eventMap, flows, deviceFlows, arguments, mux)
	}

}

func processStderr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		log.Println(scanner.Text())
	}

}

func handleOutput(output string, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	matches := regex.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) < 13 {
			continue
		}

		timestamp, err := parseTimestamp(match[1], match[2])
		if err != nil {
			fmt.Println("Error parsing timestamp:", err)
			continue
		}

		pkttype := match[3]
		origSrc := match[4]
		origDst := match[5]
		origSport := match[6]
		origDport := match[7]
		replySrc := match[8]
		replyDst := match[9]
		replySport := match[10]
		replyDsport := match[11]
		flowID := match[12]

		NewEvent(timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID, eventMap, flows, deviceFlows, arguments, mux)
	}
}

func parseTimestamp(part1, part2 string) (float64, error) {
	combined := part1 + "." + part2
	return strconv.ParseFloat(combined, 64)
}

func NewEvent(timestamp float64, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID string, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	if arguments.ConntrackStdOut {
		logEvent(timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID)
	}

	switch pkttype {
	case "SYN_RECV":
		handleSynRecvEvent(timestamp, flowID, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, eventMap)
	default:
		handleOtherEvent(timestamp, flowID, pkttype, origSrc, eventMap, flows, deviceFlows, mux)
	}
}

func parseFlows(flows *[]metrics.Flow, DeviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	promMean, promHisto, promAgMean, promAgHisto, promDeviceCount := exporter.PromExporter(arguments.PromPort, arguments.SSLCert, arguments.SSLKey, arguments.NoSSL)

	for {

		mux.Lock()

		metrics.CalculateAverages(flows, promMean, promHisto, arguments, mux)
		metrics.CalculateAggregateAverages(DeviceFlows, promAgMean, promAgHisto, promDeviceCount, arguments, mux)
		clearDeviceFlows(DeviceFlows)

		mux.Unlock()

		time.Sleep(time.Duration(arguments.StatsPeriod) * time.Second)
	}
}

func clearDeviceFlows(deviceFlows map[string][]float64) {
	for k := range deviceFlows {
		delete(deviceFlows, k)
	}
}

func logEvent(timestamp float64, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID string) {
	log.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID)
}

func handleOtherEvent(timestamp float64, flowID string, pkkytype string, origSrc string, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, mux *sync.Mutex) {
	event, present := eventMap[flowID]
	if present {
		processMatchedEvent(timestamp, flowID, origSrc, event, flows, deviceFlows, mux)
		delete(eventMap, flowID)
	}
}

func processMatchedEvent(timestamp float64, flowID, origSrc string, event map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, mux *sync.Mutex) {
	synTimestamp := event["timestamp"].(float64)
	lanRTT := metrics.CalculateFlowRtt(synTimestamp, timestamp)

	newFlow := metrics.Flow{
		FlowID:       flowID,
		DeviceIP:     origSrc,
		SynTimestamp: synTimestamp,
		AckTimestamp: timestamp,
		LanRTT:       lanRTT,
	}

	mux.Lock()
	if len(*flows) == 2000 {
		*flows = (*flows)[1:]
	}
	*flows = append(*flows, newFlow)
	updateDeviceFlows(origSrc, lanRTT, deviceFlows)
	mux.Unlock()
}

func updateDeviceFlows(deviceIP string, lanRTT float64, deviceFlows map[string][]float64) {
	deviceFlows[deviceIP] = append(deviceFlows[deviceIP], lanRTT)
}

func handleSynRecvEvent(timestamp float64, flowID, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport string, eventMap map[string]map[string]interface{}) {
	eventMap[flowID] = map[string]interface{}{
		"timestamp":   timestamp,
		"type":        pkttype,
		"origSrc":     origSrc,
		"origDst":     origDst,
		"origSport":   origSport,
		"origDport":   origDport,
		"replySrc":    replySrc,
		"replyDst":    replyDst,
		"replySport":  replySport,
		"replyDsport": replyDsport,
	}
}
