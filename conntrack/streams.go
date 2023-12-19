package conntrack

import (
	"bufio"
	"conntrack-lanrtt-analysis/exporter"
	"conntrack-lanrtt-analysis/loader"
	"conntrack-lanrtt-analysis/metrics"
	"io"
	"log"
	"regexp"
	"sync"
)

func EventParser(stdout io.ReadCloser, stderr io.ReadCloser, arguments *loader.Args, promMetrics *exporter.PromMetrics) {
	regex := compileEventRegex()

	eventMap := make(map[string]map[string]interface{})
	deviceFlows := make(map[string][]float64)
	allFlows := make([]metrics.Flow, 0, 10)
	mux := &sync.Mutex{}

	go metrics.ParseFlows(&allFlows, deviceFlows, arguments, promMetrics, mux)
	processStreams(stdout, stderr, regex, eventMap, &allFlows, deviceFlows, arguments, mux)
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
		err := handleOutput(output, regex, eventMap, flows, deviceFlows, arguments, mux)
		if err != nil {
			if arguments.Debug {
				log.Printf("error parsing conntrack string: %s", err)
			}
		}
	}

}

func processStderr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		log.Println(scanner.Text())
	}

}
