package exporter

import (
	"log"
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

// func PromExporter(promPort, sslCert, sslKey string, noSSL bool) (prometheus.Gauge, prometheus.Histogram, prometheus.Gauge, prometheus.Histogram, prometheus.Gauge) {
/*func PromExporter(promPort, sslCert, sslKey string, noSSL bool) PromMetrics {
	reg := prometheus.NewRegistry()

	promMetrics := PromMetrics{}
	promMetrics.MeanAll = newGauge("lanRtt_mean_value", "lanRtt average value")
	promMetrics.MeanAggregated = newGauge("lanRtt_aggregated_device_flows_mean_value", "lanRtt aggregated device flows average value")
	promMetrics.MeanHisto = newHistogram("lanRtt_flows_histo_value", "lanRtt flows histo values")
	promMetrics.MeanAggregatedHisto = newHistogram("lanRtt_aggregated_device_flows_histo_value", "lanRtt aggregated device flows histo values")

	/*
		promMeanEndpoint := newGauge("lanRtt_mean_value", "lanRtt average value")
		promAgMeanEndpoint := newGauge("lanRtt_aggregated_device_flows_mean_value", "lanRtt aggregated device flows average value")
		promDeviceCountEndpoint := newGauge("lanRtt_unique_device_flows_value", "lanRtt unique device flow count value")
		promHistoEndpoint := newHistogram("lanRtt_flows_histo_value", "lanRtt flows histo values")
		promAgHistoEndpoint := newHistogram("lanRtt_aggregated_device_flows_histo_value", "lanRtt aggregatred device flows histo values")

	reg.MustRegister(promMetrics.MeanAll, promMetrics.MeanAggregated, promMetrics.MeanHisto, promMetrics.MeanAggregatedHisto)
	//reg.MustRegister(promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promDeviceCountEndpoint, promAgHistoEndpoint)

	//go startHTTPServer(reg, promPort, sslCert, sslKey, noSSL)

	return promMetrics
}
*/
//return promMeanEndpoint, promHistoEndpoint, promAgMeanEndpoint, promAgHistoEndpoint, promDeviceCountEndpoint

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
				log.Panicf("error starting exporter listener: %s\n", err)
			}
		} else {
			err := http.ListenAndServeTLS(":"+options.Port, options.SSLCert, options.SSLKey, nil)
			if err != nil {
				log.Panicf("error starting exporter listener: %s\n", err)
			}
		}
	}(reg)

	return reg
	/*
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
	*/
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
