# Scan uses the DNS cache for host names

The scan maps remote IPs to host names using the local DNS client cache instead of reverse DNS lookups. Lookups would generate network traffic, could alert a remote operator, and often return a hosting provider's name rather than the pool domain the process actually requested. The cost is that a connection whose name has left the cache shows a blank host, so host-based flags can miss it. Port-based flags still apply.
