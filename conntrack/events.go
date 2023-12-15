package conntrack

import (
	"conntrack-lanrtt-analysis/loader"
	"conntrack-lanrtt-analysis/metrics"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"sync"
)

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
		handleAckEvent(timestamp, flowID, pkttype, origSrc, eventMap, flows, deviceFlows, arguments.BufferSize, mux)
	}
}

func logEvent(timestamp float64, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID string) {
	log.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", timestamp, pkttype, origSrc, origDst, origSport, origDport, replySrc, replyDst, replySport, replyDsport, flowID)
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

func handleAckEvent(timestamp float64, flowID string, pkkytype string, origSrc string, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, bufferSize int, mux *sync.Mutex) {
	event, present := eventMap[flowID]
	if present {
		processMatchedEvent(timestamp, flowID, origSrc, event, flows, deviceFlows, bufferSize, mux)
		delete(eventMap, flowID)
	}
}

func processMatchedEvent(timestamp float64, flowID, origSrc string, event map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, bufferSize int, mux *sync.Mutex) {
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

	if len(*flows) == bufferSize {
		*flows = (*flows)[1:]
	}
	*flows = append(*flows, newFlow)
	updateDeviceFlows(origSrc, lanRTT, deviceFlows)
	mux.Unlock()
}

func updateDeviceFlows(deviceIP string, lanRTT float64, deviceFlows map[string][]float64) {
	deviceFlows[deviceIP] = append(deviceFlows[deviceIP], lanRTT)
}
