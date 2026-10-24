package botdetect

import (
	"fmt"
	"strings"

	"github.com/LumenResearch/uasurfer"
)

// == USER AGENT PARSING =======================================================

// Browser names returned by ParseUserAgent. All values are lowercase —
// display formatting (e.g. "macos" → "macOS") is left to consumers.
const (
	BrowserEdge = "edge"
)

// OS names returned by ParseUserAgent.
const (
	OsMacOS = "macos"
	OsIOS   = "ios"
)

// Device names returned by ParseUserAgent.
const (
	DeviceIPhone = "iphone"
	DeviceIPad   = "ipad"
	DeviceIPod   = "ipod"
)

// Device types returned by ParseUserAgent in UserAgentInfo.DeviceType.
const (
	DeviceTypeDesktop = "desktop"
	DeviceTypeMobile  = "mobile"
	DeviceTypeTablet  = "tablet"
	DeviceTypeTV      = "tv"
)

// Bot is the value uasurfer-derived fields (DeviceType, Browser, Device)
// take when the user-agent is classified as a bot.
const Bot = "bot"

// UserAgentInfo holds parsed user-agent data.
type UserAgentInfo struct {
	Browser        string
	BrowserVersion string
	Os             string
	OsVersion      string
	Device         string
	DeviceType     string
}

// ParseUserAgent extracts browser, OS, device, and device-type from a
// user-agent string using the uasurfer library. Unknown values are left
// as empty strings. All name fields are normalized to lowercase so
// consumers can compare them without case-folding.
func ParseUserAgent(ua string) UserAgentInfo {
	info := UserAgentInfo{}
	if ua == "" {
		return info
	}

	parsed := uasurfer.Parse(ua)

	// Browser — uasurfer lacks an Edge constant, so detect it from the
	// tokens Edge (Chromium) includes in its UA string: "Edg/" on
	// desktop, "EdgA/" on Android, "EdgiOS/" on iOS. The version is read
	// from the Edge token itself, since uasurfer may attribute the
	// Version/ token (Safari's version on iOS) instead.
	for _, token := range []string{"EdgiOS/", "EdgA/", "Edg/"} {
		if i := strings.Index(ua, token); i >= 0 {
			info.Browser = BrowserEdge
			info.BrowserVersion = tokenVersion(ua[i+len(token):])
			break
		}
	}
	if info.Browser == "" && parsed.Browser.Name != uasurfer.BrowserUnknown {
		info.Browser = strings.ToLower(parsed.Browser.Name.StringTrimPrefix())
		info.BrowserVersion = versionToString(parsed.Browser.Version)
	}

	// OS
	if parsed.OS.Name != uasurfer.OSUnknown {
		info.Os = osNameToString(parsed.OS.Name)
	}

	// OS version
	info.OsVersion = versionToString(parsed.OS.Version)

	// Device name (from platform)
	switch parsed.OS.Platform {
	case uasurfer.PlatformiPhone:
		info.Device = DeviceIPhone
	case uasurfer.PlatformiPad:
		info.Device = DeviceIPad
	case uasurfer.PlatformiPod:
		info.Device = DeviceIPod
	}

	// Device type
	info.DeviceType = deviceTypeToString(parsed.DeviceType)

	return info
}

// tokenVersion extracts a "major.minor" version from the start of a UA
// token value (e.g. "120.0.0.0 " → "120.0"), matching the format produced
// by versionToString.
func tokenVersion(s string) string {
	end := strings.IndexAny(s, " )")
	if end >= 0 {
		s = s[:end]
	}
	parts := strings.Split(s, ".")
	switch {
	case len(parts) >= 3 && parts[2] != "0":
		return strings.Join(parts[:3], ".")
	case len(parts) >= 2:
		return strings.Join(parts[:2], ".")
	default:
		return s
	}
}

// osNameToString maps uasurfer OSName constants to human-readable strings.
func osNameToString(name uasurfer.OSName) string {
	switch name {
	case uasurfer.OSMacOSX:
		return OsMacOS
	case uasurfer.OSiPadOS:
		return OsIOS
	default:
		return strings.ToLower(name.StringTrimPrefix())
	}
}

// versionToString formats a uasurfer.Version as "major.minor" or
// "major.minor.patch" (when patch > 0). Returns empty string if major is 0.
func versionToString(v uasurfer.Version) string {
	if v.Major == 0 {
		return ""
	}
	if v.Patch > 0 {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

// deviceTypeToString maps uasurfer DeviceType constants to the lowercase
// values expected by the admin UI (desktop, mobile, tablet).
func deviceTypeToString(dt uasurfer.DeviceType) string {
	switch dt {
	case uasurfer.DeviceComputer:
		return DeviceTypeDesktop
	case uasurfer.DevicePhone:
		return DeviceTypeMobile
	case uasurfer.DeviceTablet:
		return DeviceTypeTablet
	case uasurfer.DeviceTV:
		return DeviceTypeTV
	case uasurfer.DeviceUnknown:
		return ""
	default:
		return strings.ToLower(dt.StringTrimPrefix())
	}
}
