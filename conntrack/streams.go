package conntrack

import (
	"bufio"
	"conntrack-lanrtt-analysis/lanrtt/loader"
	"conntrack-lanrtt-analysis/lanrtt/metrics"
	"io"
	"log"
	"regexp"
	"sync"
)

func EventParser(stdout io.ReadCloser, stderr io.ReadCloser, arguments *loader.Args) {
	regex := compileEventRegex()

	eventMap := make(map[string]map[string]interface{})
	deviceFlows := make(map[string][]float64)
	flows := make([]metrics.Flow, 0, 10)
	mux := &sync.Mutex{}

	go metrics.ParseFlows(&flows, deviceFlows, arguments, mux)
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