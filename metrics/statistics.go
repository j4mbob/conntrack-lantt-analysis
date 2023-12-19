package metrics

import (
	"conntrack-lanrtt-analysis/exporter"
	"conntrack-lanrtt-analysis/loader"
	"log"
	"sync"
	"time"
)

type Flow struct {
	FlowID       string
	DeviceIP     string
	SynTimestamp float64
	AckTimestamp float64
	LanRTT       float64
}

func ParseFlows(allFlows *[]Flow, DeviceFlows map[string][]float64, arguments *loader.Args, promMetrics *exporter.PromMetrics, mux *sync.Mutex) {

	for {

		mux.Lock()

		CalculateAverages(allFlows, arguments, promMetrics, mux)
		CalculateAggregateAverages(DeviceFlows, arguments, promMetrics, mux)
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

func CalculateFlowRtt(synTimestamp, ackTimestamp float64) float64 {
	return (ackTimestamp - synTimestamp) * 1000
}

func CalculateAverages(allFlows *[]Flow, args *loader.Args, promMetrics *exporter.PromMetrics, mux *sync.Mutex) {
	var delayTotal, mean float64

	for _, flow := range *allFlows {
		delayTotal += flow.LanRTT
		promMetrics.MeanHisto.Observe(flow.LanRTT)

	}
	flowCount := len(*allFlows)

	if flowCount > 0 {
		mean = delayTotal / float64(flowCount)
	}

	promMetrics.MeanAll.Set(mean)

	logFlowStats(args, delayTotal, flowCount, mean)
}

func logFlowStats(args *loader.Args, delayTotal float64, flowCount int, mean float64) {
	if args.StatsStdOut {
		log.Printf("All Flows: [delayTotal: %f] [Flowcount: %d] [LAN Rtt: %f]\n", delayTotal, flowCount, mean)
	}
}

func CalculateAggregateAverages(deviceFlows map[string][]float64, args *loader.Args, promMetrics *exporter.PromMetrics, mux *sync.Mutex) {
	var devicesCount int
	var devicesMean float64

	for _, v := range deviceFlows {
		mean := CalculateMean(v)
		devicesMean += mean
		promMetrics.MeanAggregatedHisto.Observe(mean)

	}
	devicesCount = len(deviceFlows)

	if devicesCount > 0 {
		devicesMean /= float64(devicesCount)
	}

	promMetrics.DeviceCount.Set(float64(devicesCount))

	promMetrics.MeanAggregated.Set(devicesMean)

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
