
 # SlowSoftSerial Test Packets Decoder

This is an extension for Saleae's Logic 2 software for use with
their series of logic analyzers. It decodes the protocol used for
testing [SlowSoftSerial](https://github.com/MustBeArt/SlowSoftSerial).

## Getting started

Attach one of these to Async Serial analyzer for CTRL --> UUT
and another one to the Async Serial analyzer for UUT --> CTRL

Displays decoded information from the packets, but is not able to
follow the baud rate and configuration changes required by the
protocol. So you will only see packet decodes on those parts of
the capture that match the baud rate and configuration currently
set in the Async Serial analyzers.