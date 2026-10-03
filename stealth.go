package main

import (
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Which browser hello to imitate.
//
// The setting used to be read and ignored: whatever was written, the hello was
// always the library's default Chrome. That is worth fixing for its own sake, and
// also because the default moves on with each library release, so a tunnel
// written to say "chrome" should follow it while one that names a specific
// version stays put.
var utlsProfileIDs = map[string]utls.ClientHelloID{
	"chrome":            utls.HelloChrome_Auto,
	"chrome_120":        utls.HelloChrome_120,
	"chrome_120_pq":     utls.HelloChrome_120_PQ,
	"chrome_115_pq":     utls.HelloChrome_115_PQ,
	"chrome_115_pq_psk": utls.HelloChrome_115_PQ_PSK,
	"firefox":           utls.HelloFirefox_Auto,
	"safari":            utls.HelloSafari_Auto,
	"ios":               utls.HelloIOS_Auto,
	"edge":              utls.HelloEdge_Auto,
}

// utlsProfileNames lists the profile names for an error message.
func utlsProfileNames() string {
	names := make([]string, 0, len(utlsProfileIDs))
	for n := range utlsProfileIDs {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// utlsHelloID is the hello to imitate for this configuration.
func (c *Config) utlsHelloID() utls.ClientHelloID {
	if id, ok := utlsProfileIDs[strings.ToLower(c.UTLSProfile)]; ok {
		return id
	}
	return utls.HelloChrome_Auto
}
