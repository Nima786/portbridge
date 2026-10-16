package engine

// What the engine shows other parts of PortBridge (the agent and the panel), so
// they describe a tunnel in the same words the log and the menu use.

// DescribeLink says in plain words what a tunnel's link looks like on the wire.
func DescribeLink(cfg *Config) string { return describeTransport(cfg) }
