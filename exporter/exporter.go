package exporter

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func PromExporter(promPort, sslCert, sslKey string, noSSL bool) (prometheus.Gauge, prometheus.Histogram, prometheus.Gauge, prometheus.Histogram, prometheus.Gauge) {
	reg := prometheus.NewRegistry()

	promMeanEndpoint := newGauge("lanRtt_mean_value", "lanRtt average value")
	promAgMeanEndpoint := newGauge("lanRtt_aggregated_device_flows_mean_value", "lanRtt aggregated device flows average value")
	promDeviceCountEndpoint := newGauge("lanRtt_unique_device_flows_value", "lanRtt unique device flow count value")
	promHistoEndpoint := newHistogram("lanRtt_flows_histo_value", "lanRtt flows histo values")
	promAgHistoEndpoint := newHistogram("lanRtt_aggregated_device_flows_histo_value", "lanRtt aggregatred device flows histo values")

	reg.MustRegister(promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promDeviceCountEndpoint, promAgHistoEndpoint)

	go startHTTPServer(reg, promPort, sslCert, sslKey, noSSL)

	return promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promAgHistoEndpoint, promDeviceCountEndpoint
}

func newGauge(name, help string) prometheus.Gauge {
	return promauto.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

func newHistogram(name, help string) prometheus.Histogram {
	return promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})
}

func startHTTPServer(reg *prometheus.Registry, promPort, sslCert, sslKey string, noSSL bool) {
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	var err error
	if noSSL {
		err = http.ListenAndServe(":"+promPort, nil)
	} else {
		err = http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}
