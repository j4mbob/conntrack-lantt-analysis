package main

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

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
