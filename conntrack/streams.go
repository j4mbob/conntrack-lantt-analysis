package conntrack

import (
	"bufio"
	"conntrack-lanrtt-analysis/exporter"
	"conntrack-lanrtt-analysis/loader"
	"conntrack-lanrtt-analysis/metrics"
	"fmt"
	"io"
	"regexp"
	"sync"
)

func EventParser(stdout io.ReadCloser, stderr io.ReadCloser, arguments *loader.Args, promMetrics *exporter.PromMetrics) {
	regex := compileEventRegex()

	// map of individual unique events i.e each SYN_RECV event and each ESTABLISHED event
	eventMap := make(map[string]map[string]interface{})

	// map of each device and its flow's RTT values
	deviceFlows := make(map[string][]float64)

	// Flow structs for every unique flow (the SYN_RECV and its corresponding ESTABLISHED) during the capture period
	allFlows := make([]metrics.Flow, 0, 10)

	mux := &sync.Mutex{}

	go metrics.ParseFlows(&allFlows, deviceFlows, arguments, promMetrics, mux)
	processStreams(stdout, stderr, regex, eventMap, &allFlows, deviceFlows, arguments, mux)
}

func compileEventRegex() *regexp.Regexp {
	pattern := `^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`
	return regexp.MustCompile(pattern)
}

func processStreams(stdout, stderr io.ReadCloser, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, allFlows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	go processStdout(stdout, regex, eventMap, allFlows, deviceFlows, arguments, mux)
	go processStderr(stderr)
}

func processStdout(stdout io.ReadCloser, regex *regexp.Regexp, eventMap map[string]map[string]interface{}, allFlows *[]metrics.Flow, deviceFlows map[string][]float64, arguments *loader.Args, mux *sync.Mutex) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		output := scanner.Text()
		err := handleOutput(output, regex, eventMap, allFlows, deviceFlows, arguments, mux)
		if err != nil {
			if arguments.Debug {
				fmt.Printf("error parsing conntrack string: %v\n", err)
			}
		}
	}

}

func processStderr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}

}
