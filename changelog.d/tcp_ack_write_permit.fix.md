TCP-based sources now release the `RequestLimiter` permit before writing an acknowledgement, and
bound that write with a 30-second timeout. Previously a peer that stopped reading could hold a
permit indefinitely and starve other connections.
