package botdetect

import "testing"

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want UserAgentInfo
	}{
		{
			name: "Firefox on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
			want: UserAgentInfo{
				Browser:        "firefox",
				BrowserVersion: "153.0",
				Os:             "windows",
				OsVersion:      "10.0",
				DeviceType:     "desktop",
			},
		},
		{
			name: "Chrome on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			want: UserAgentInfo{
				Browser:        "chrome",
				BrowserVersion: "120.0",
				Os:             "windows",
				OsVersion:      "10.0",
				DeviceType:     "desktop",
			},
		},
		{
			name: "Edge on Windows",
			ua:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			want: UserAgentInfo{
				Browser:        "edge",
				BrowserVersion: "120.0",
				Os:             "windows",
				OsVersion:      "10.0",
				DeviceType:     "desktop",
			},
		},
		{
			name: "Safari on macOS",
			ua:   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
			want: UserAgentInfo{
				Browser:        "safari",
				BrowserVersion: "17.1",
				Os:             "macos",
				OsVersion:      "10.15.7",
				DeviceType:     "desktop",
			},
		},
		{
			name: "Chrome on Android mobile",
			ua:   "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
			want: UserAgentInfo{
				Browser:        "chrome",
				BrowserVersion: "120.0",
				Os:             "android",
				OsVersion:      "13.0",
				DeviceType:     "mobile",
			},
		},
		{
			name: "Safari on iPhone",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			want: UserAgentInfo{
				Browser:        "safari",
				BrowserVersion: "17.2",
				Os:             "ios",
				OsVersion:      "17.2",
				Device:         "iphone",
				DeviceType:     "mobile",
			},
		},
		{
			name: "Safari on iPad",
			ua:   "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
			want: UserAgentInfo{
				Browser:        "safari",
				BrowserVersion: "17.2",
				Os:             "ios",
				OsVersion:      "17.2",
				Device:         "ipad",
				DeviceType:     "tablet",
			},
		},
		{
			name: "Edge on Android",
			ua:   "Mozilla/5.0 (Linux; Android 10; ONEPLUS A6003) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0",
			want: UserAgentInfo{
				Browser:        "edge",
				BrowserVersion: "120.0",
				Os:             "android",
				OsVersion:      "10.0",
				DeviceType:     "mobile",
			},
		},
		{
			name: "Edge on iOS",
			ua:   "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) EdgiOS/120.0.0.0 Version/17.0 Mobile/15E148 Safari/605.1.15",
			want: UserAgentInfo{
				Browser:        "edge",
				BrowserVersion: "120.0",
				Os:             "ios",
				OsVersion:      "17.2",
				Device:         "iphone",
				DeviceType:     "mobile",
			},
		},
		{
			name: "Empty UA",
			ua:   "",
			want: UserAgentInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUserAgent(tt.ua)
			if got != tt.want {
				t.Errorf("ParseUserAgent(%q)\n  got:  %+v\n  want: %+v", tt.ua, got, tt.want)
			}
		})
	}
}
