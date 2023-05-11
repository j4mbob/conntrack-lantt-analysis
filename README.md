# conntrack-lanrtt-analysis

Samples conntrack data to produce lan-rtt stats for site traffic

## Getting started

```
./lanrtt -h
Usage of ./lanrtt:
  -buffersize int
    	number of events to buffer for calculations (default 1000)
  -conntrackoutput
    	output conntrack updates to stdout
  -continuous
    	run continuously
  -loadconfig string
    	load json config file. defaults to lanrtt.json (default "none")
  -mask string
    	subnet mask to use (default "255.255.240.0")
  -network string
    	network address to filter for (default "127.0.0.1")
  -nossl
    	set to use HTTP and not HTTPS for Prom exporter
  -pollingtime int
    	duration in seconds to poll for (default 300)
  -promport string
    	port for prom exporter to listen on (default "1986")
  -sslcert string
    	path to SSL cert to use for prom exporter
  -sslkey string
    	path to SSL priv key to use for prom exporter
  -statsoutput
    	output stats updates to stdout
  -statsperiod int
    	output stats every x seconds (default 5)
```


Arguments can also be read from a JSON file loaded via -loadconfig <path> .  this defaults to lanrtt.json in the same directory as the binary

example file is in the repo
