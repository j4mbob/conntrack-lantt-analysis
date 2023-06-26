package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func PromExporter(promPort string, sslCert string, sslKey string, noSSL bool) (prometheus.Gauge, prometheus.Histogram, prometheus.Gauge, prometheus.Histogram, prometheus.Gauge) {

	reg := prometheus.NewRegistry()

	promMeanEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_mean_value",
		Help: "lanRtt average value",
	})

	promAgMeanEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_aggregated_device_flows_mean_value",
		Help: "lanRtt aggregated device flows average value",
	})

	promDeviceCountEndpoint := promauto.NewGauge(prometheus.GaugeOpts{
		Name: "lanRtt_unique_device_flows_value",
		Help: "lanRtt unique device flow count value",
	})

	promHistoEndpoint := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lanRtt_flows_histo_value",
		Help:    "lanRtt flows histo values",
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	promAgHistoEndpoint := promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "lanRtt_aggregated_device_flows_histo_value",
		Help:    "lanRtt aggregatred device flows histo values",
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	reg.MustRegister(promMeanEndpoint)
	reg.MustRegister(promHistoEndpoint)
	reg.MustRegister(promAgMeanEndpoint)
	reg.MustRegister(promDeviceCountEndpoint)
	reg.MustRegister(promAgHistoEndpoint)

	go func(reg *prometheus.Registry) {
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		if noSSL {
			log.Fatal(http.ListenAndServe(":"+promPort, nil))

		} else {
			log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
		}
		log.Fatal(http.ListenAndServeTLS(":"+promPort, sslCert, sslKey, nil))
	}(reg)

	return promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promAgHistoEndpoint, promDeviceCountEndpoint

}
