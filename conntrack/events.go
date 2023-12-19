package conntrack

import (
	"conntrack-lanrtt-analysis/loader"
	"conntrack-lanrtt-analysis/metrics"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"sync"
)

type event struct {
	TimeStamp       float64
	PacketType      string
	OriginalSrc     string
	OriginalDst     string
	OriginalSrcPort string
	OriginalDstPort string
	ReplySrc        string
	ReplyDst        string
	ReplySrcPort    string
	ReplyDstPort    string
	FlowID          string
}

func handleOutput(output string, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) error {
	matches := regex.FindAllStringSubmatch(output, -1)
	if matches == nil {
		return errors.New("no regex match for conntrack output")
	}
	for _, match := range matches {
		if len(match) != 13 {
			return errors.New("conntrack string too short")
		} else {

			timestamp, err := parseTimestamp(match[1], match[2])
			if err != nil {
				fmt.Println("Error parsing timestamp:", err)
				continue
			}
			newEvent := event{}
			newEvent.TimeStamp = timestamp
			newEvent.PacketType = match[3]
			newEvent.OriginalSrc = match[4]
			newEvent.OriginalDst = match[5]
			newEvent.OriginalSrcPort = match[6]
			newEvent.OriginalDstPort = match[7]
			newEvent.ReplySrc = match[8]
			newEvent.ReplyDst = match[9]
			newEvent.ReplySrcPort = match[10]
			newEvent.ReplyDstPort = match[11]
			newEvent.FlowID = match[12]

			err = processNewEvent(newEvent, eventMap, flows, deviceFlows, arguments, mux)
			if err != nil {
				return err
			}

		}
	}
	return nil
}

func parseTimestamp(part1, part2 string) (float64, error) {
	combined := part1 + "." + part2
	return strconv.ParseFloat(combined, 64)
}

func processNewEvent(newEvent event, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) error {

	switch newEvent.PacketType {
	case "SYN_RECV":
		handleSynRecvEvent(newEvent, eventMap)

	case "ESTABLISHED":
		handleAckEvent(newEvent, eventMap, flows, deviceFlows, arguments.BufferSize, mux)
	default:
		return errors.New("no valid event type")
	}

	if arguments.ConntrackStdOut {
		logEvent(newEvent)
	}

	return nil

}

func logEvent(newEvent event) {
	log.Printf("[%f] %v %v %v %v %v %v %v %v %v %v\n", newEvent.TimeStamp, newEvent.PacketType, newEvent.OriginalSrc, newEvent.OriginalDst, newEvent.OriginalSrcPort, newEvent.OriginalDstPort, newEvent.ReplySrc,
		newEvent.ReplyDst, newEvent.ReplySrcPort, newEvent.ReplyDstPort, newEvent.FlowID)
}

func handleSynRecvEvent(newEvent event, eventMap map[string]map[string]interface{}) {
	eventMap[newEvent.FlowID] = map[string]interface{}{
		"timestamp":   newEvent.TimeStamp,
		"type":        newEvent.PacketType,
		"origSrc":     newEvent.OriginalSrc,
		"origDst":     newEvent.OriginalDst,
		"origSport":   newEvent.OriginalSrcPort,
		"origDport":   newEvent.OriginalDstPort,
		"replySrc":    newEvent.ReplySrc,
		"replyDst":    newEvent.ReplyDst,
		"replySport":  newEvent.ReplySrcPort,
		"replyDsport": newEvent.ReplyDstPort,
	}
}

func handleAckEvent(newEvent event, eventMap map[string]map[string]interface{}, flows *[]metrics.Flow, deviceFlows map[string][]float64, bufferSize int, mux *sync.Mutex) {
	synRecvEvent, present := eventMap[newEvent.FlowID]
	if present {
		processMatchedEvent(newEvent.TimeStamp, newEvent.FlowID, newEvent.OriginalSrc, synRecvEvent, flows, deviceFlows, bufferSize, mux)
		delete(eventMap, newEvent.FlowID)
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
