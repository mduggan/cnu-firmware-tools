## Patches for C toolchain to support Cisco 7900 Series IP Phone Unix / MIPS

A long time ago while working for Qualcomm Product Security, I developed some
tools to own Cisco IP 7900 series phones remotely.

There were two main (long since fixed) vulnrabilities which combined to a full
remote root of the device, assuming you had a "close enough" network:
* A TFTP flood attack which could be used to knock the phone off the network,
  front-run the real config server, and bypass configuration signing
  requirements (allowing default telnet access even if it had been disabled
  centrally)
* A local `sudo` bypass, bypassing the null shell by reversing their custom
  hash challenge and setting `PATH` environment

The latter was caused by the contents of `/bin/nologin` being:
```
#!/bin/sh
slog LOG_EMERG Attempt to login to disabled account.
echo 'This account is currently not available.'
exit 1
```
Their sudo does not scrub environment, so we can just make a better `slog` in
`/tmp` and change `$PATH`, then it will run as root.

The problems were reported to Cisco, fixed and published many years ago.  They
rated it low severity, although in practice it effectively allowed me to turn
desk phones into remote listening devices:
https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20110601-phone.html

That was fun and all, but after having root the natural question is what do you
do next?  To develop really fun tools you need a compiler and toolchain for
the OS, which doesn't exist publically.

This repo contains the minimal patches I created for the GNU C toolchain and
"newlib" (a minimal C library perfect for this application) to support
compilation of CNU (Cisco IP Phone Unix) MIPS binaries.  With this I was able
to display whatever I wanted on the phone screens (using their very slow ioctl
interface).  It was enough to amuse me and my colleagues.

This repo also has a few tools I made in the process which might be interesting.

I'm uploading them 14 years later in case anyone else finds them interesting
and really wants to know what syscall numbers CNU uses or how its ioctls work.
I'm not really aware of other online resources documenting this stuff, and it
should be properly patched everywhere by now!

There's very little documentation, but if you really want to know more about it
then email me.

Random notes:
* CNU's SSH server is a modified version of dropbear
* One binary had symbols (ping), that was helpful
* Final question.. who are RICKANDJENNIFERW?
* This tool was useful: https://github.com/kbdfck/cnu-fpu


**Matthew Duggan - Jul 2025**
