
# Installation Tutorial

The below steps will help you install the Wireshark WSGD dissector for OpenSIPS
binary interface packets, so you can start developing code, troubleshooting bugs
or simply visualize and better understand how the binary interface works.

## Installing WSGD (Wireshark Generic Dissector)

WSGD is a C++ Wireshark plugin which offers a bespoke language, perfect for
easily putting together (and maintaining) Wireshark dissectors intuitively, with
a minimal amount of required code.  To install it:

* go to http://wsgd.free.fr/download.html and download the `generic.so` archive
  corresponding to your installed Wireshark version.  You can view the version
  in the Help -> About Wireshark menu.

* extract the archive using `tar xvf generic.so...`, then place the `generic.so`
  file in the Wireshark plugins directory of your system.  In my case, it was
  `/usr/lib/x86_64-linux-gnu/wireshark/plugins/2.6/epan/`.  YMMV.  Some extra
  tips are available here: http://wsgd.free.fr/installation.html

* you can confirm that the plugin gets loaded by re-opening Wireshark and viewing
  Help -> About Wireshark -> Plugins.  Make sure "generic.so" is listed there,
  otherwise the OpenSIPS binary interface dissector files won't get interpreted.

## Installing the OpenSIPS BIN dissector

Once you've got `generic.so` working, just copy both files of the dissector
(`opensips.wsgd` and `opensips.fdesc`) into the same plugins directory where
you placed `generic.so` and restart Wireshark.

You should now be able to parse "OPENSIPS-BIN" protocol packets, compatible
with versions 2.4 and above!  Have fun!
