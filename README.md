# conntrack-lanrtt-analysis

Samples conntrack data to produce lan-rtt stats for a specific subnet

## Getting started

```
./lanrtt -h
Usage of ./lanrtt:
  -buffersize int
    	number of events to buffer for calculations (default 2000)
  -continuous
    	run continuously
  -debug
    	enabling debugging
  -loadconfig string
    	load json config file (default "none")
  -mask string
    	subnet mask to use (default "255.255.240.0")
  -network string
    	network address to filter for (default "127.0.0.1")
  -pdfile string
    	pid file to use (default "/run/lanrtt.pid")
  -pollingtime int
    	duration in seconds to poll for (default 300)
  -promport string
    	port for prom exporter to listen on (default "1986")
  -pyroscope
    	sent application metrics to remote pyroschope host
  -pyroscopehost string
    	remote pyroscope host to uset (default "http://pyroscope-host:4040")
  -sslcert string
    	path to SSL cert to use for prom exporter
  -sslkey string
    	path to SSL priv key to use for prom exporter
  -statsout
    	output stats updates to stdout
  -statsperiod int
    	output stats every x seconds (default 5)
  -usessl
    	set to use HTTP and not HTTPS for Prom exporter
```


Arguments can also be read from a JSON file loaded via -loadconfig

to run continously ensure continuous is set. pollingtime is ignored if continuous is enabled. Statsperiod and buffersize can be left on the defaults

example config file is in the repo

