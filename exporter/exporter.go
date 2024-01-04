package exporter

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type PromMetrics struct {
	MeanAll             prometheus.Gauge
	MeanAggregated      prometheus.Gauge
	MeanHisto           prometheus.Histogram
	MeanAggregatedHisto prometheus.Histogram
	DeviceCount         prometheus.Gauge
}

type ExporterOpts struct {
	Port    string
	SSLCert string
	SSLKey  string
	UseSSL  bool
}

func newGauge(reg *prometheus.Registry, name, help string) prometheus.Gauge {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
	reg.MustRegister(gauge)
	return gauge

}

func newHistogram(reg *prometheus.Registry, name, help string) prometheus.Histogram {
	histo := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    name,
		Help:    help,
		Buckets: prometheus.LinearBuckets(5, 10, 20),
	})

	reg.MustRegister(histo)

	return histo
}

func StartPromEndPoint(options ExporterOpts) *prometheus.Registry {

	reg := prometheus.NewRegistry()

	go func(reg *prometheus.Registry) {
		http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
		if !options.UseSSL {
			err := http.ListenAndServe(":"+options.Port, nil)
			if err != nil {
				fmt.Printf("error starting exporter listener: %v\n", err)
				panic(1)
			}
		} else {
			err := http.ListenAndServeTLS(":"+options.Port, options.SSLCert, options.SSLKey, nil)
			if err != nil {
				fmt.Printf("error starting exporter listener: %v\n", err)
				panic(1)
			}
		}
	}(reg)

	return reg

}

func BuildPromMetrics(reg *prometheus.Registry) *PromMetrics {
	return &PromMetrics{
		MeanAll:             newGauge(reg, "lanRtt_mean_value", "lanRtt average value"),
		MeanAggregated:      newGauge(reg, "lanRtt_aggregated_device_flows_mean_value", "lanRtt aggregated device flows average value"),
		MeanHisto:           newHistogram(reg, "lanRtt_flows_histo_value", "lanRtt flows histo values"),
		MeanAggregatedHisto: newHistogram(reg, "lanRtt_aggregated_device_flows_histo_value", "lanRtt aggregated device flows histo values"),
		DeviceCount:         newGauge(reg, "lanRtt_unique_device_flows_value", "lanRtt unique device flow count value"),
	}

}
