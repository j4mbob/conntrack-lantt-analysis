package conntrack

import (
	"conntrack-lanrtt-analysis/loader"
	"conntrack-lanrtt-analysis/metrics"
	"errors"
	"regexp"
	"sync"
	"testing"
)

func TestHandleOutput(t *testing.T) {
	regexPattern := `^\[([0-9]+)\.([0-9]+) *\].*(SYN_RECV|ESTABLISHED) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) src=([^ ]+) dst=([^ ]+) sport=([^ ]+) dport=([^ ]+) (?:\[ASSURED\] )?id=([0-9]+)$`
	regex := regexp.MustCompile(regexPattern)

	testCases := []struct {
		name          string
		output        string
		expectedError error
	}{
		{
			name:          "ValidOutput",
			output:        "[1702972533.340676]	 [UPDATE] tcp      6 432000 ESTABLISHED src=10.152.4.231 dst=173.222.210.216 sport=51679 dport=443 src=173.222.210.216 dst=31.205.218.167 sport=443 dport=51679 [ASSURED] id=2858042624",
			expectedError: nil,
		},
		{
			name:          "NoRegexMatch",
			output:        "[1702972533.785766]	 [UPDATE] tcp      6 120 FIN_WAIT src=10.152.10.141 dst=104.91.71.86 sport=62689 dport=443 src=104.91.71.86 dst=31.205.218.184 sport=443 dport=62689 [ASSURED] id=3451258432",
			expectedError: errors.New("no regex match for conntrack output"),
		},
		{
			name:          "NoRegexMatch",
			output:        "[1702972533.349065]	 [UPDATE] tcp      120 FIN_WAIT src=10.152.4.231 dst=173.222.210.216 sport=51679 dport=443 src=173.222.210.216 dst=31.205.218.167",
			expectedError: errors.New("no regex match for conntrack output"),
		},
		{
			name:          "ValidOutput",
			output:        "[1702972533.997256]	 [UPDATE] tcp      6 60 SYN_RECV src=10.152.11.29 dst=61.170.79.234 sport=58765 dport=443 src=61.170.79.234 dst=31.205.218.180 sport=443 dport=58765 id=2857185344",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// empty mocks
			eventMap := make(map[string]map[string]interface{})
			var flows []metrics.Flow
			deviceFlows := make(map[string][]float64)
			arguments := &loader.Args{}
			mux := &sync.Mutex{}

			err := handleOutput(tc.output, regex, eventMap, &flows, deviceFlows, arguments, mux)

			if (err != nil && tc.expectedError == nil) || (err == nil && tc.expectedError != nil) || (err != nil && tc.expectedError != nil && err.Error() != tc.expectedError.Error()) {
				t.Errorf("Test %v: Expected error %v, got %v", tc.name, tc.expectedError, err)
			}

		})
	}
}
