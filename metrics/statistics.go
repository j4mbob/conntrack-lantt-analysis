package metrics

import (
	"conntrack-lanrtt-analysis/lanrtt/loader"
	"log"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type Flow struct {
	FlowID       string
	DeviceIP     string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
}

func CalculateFlowRtt(synTimestamp, ackTimestamp float64) float64 {
	return (ackTimestamp - synTimestamp) * 1000
}

func CalculateAverages(flows *[]Flow, promMean prometheus.Gauge, promHisto prometheus.Histogram, args *loader.Args, mux *sync.Mutex) {
	var delayTotal, mean float64

	for _, flow := range *flows {
		delayTotal += flow.LanRTT
		promHisto.Observe(flow.LanRTT)
	}
	flowCount := len(*flows)

	if flowCount > 0 {
		mean = delayTotal / float64(flowCount)
	}

	promMean.Set(mean)
	logFlowStats(args, delayTotal, flowCount, mean)
}

func logFlowStats(args *loader.Args, delayTotal float64, flowCount int, mean float64) {
	if args.StatsStdOut {
		log.Printf("All Flows: [delayTotal: %f] [Flowcount: %d] [LAN Rtt: %f]\n", delayTotal, flowCount, mean)
	}
}

func CalculateAggregateAverages(deviceFlows map[string][]float64, promAgMean prometheus.Gauge, promAgHisto prometheus.Histogram, promDeviceCount prometheus.Gauge, args *loader.Args, mux *sync.Mutex) {
	var devicesCount int
	var devicesMean float64

	for _, v := range deviceFlows {
		mean := CalculateMean(v)
		devicesMean += mean
		promAgHisto.Observe(mean)
	}
	devicesCount = len(deviceFlows)

	if devicesCount > 0 {
		devicesMean /= float64(devicesCount)
	}

	promDeviceCount.Set(float64(devicesCount))
	promAgMean.Set(devicesMean)
	logAggregateStats(args, devicesCount, devicesMean)
}

func logAggregateStats(args *loader.Args, devicesCount int, aggregatedMean float64) {
	if args.StatsStdOut {
		log.Printf("Aggregated Per Device: [Total Device Count: %v] [Aggregated Mean LAN Rtt: %v]\n", devicesCount, aggregatedMean)
	}
}

func CalculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}
