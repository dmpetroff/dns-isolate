# Network isolator

This is a rough replacement of `iptables -m owner --cmd-owner`: it hooks
`getaddrinfo()`, remembers last set of addresses for the host set at compile
time, and then blocks `connect()` calls to that addresses.

## Building
Create `Makefile.local` with the following contents:
```
CFLAGS := $(CFLAGS) -DISOLATE_CNAME=\"host.name.to-isolate\"
```

Then
```
make
```

Then add resulting shared library to the `LD_PRELOAD` environment variable to
command line
```
LD_PRELOAD=./dns-isolate.so your-binary
```

## Limitations
- only one cname can be specified at compile-time
- only `getaddrinfo()` is intercepted, `gethostbyname()` functions family is
  is not handled
- race conditions are likely to appear in multi-threaded environment where
  `getaddrinfo()` and connect are called in parallel. But that won't cause
  segfaults as program operates entirely in static buffer.
- statically linked binaries and custom resolvers will completely bypass
  this filter
