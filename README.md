ASN.1 toolbox for Burp Suite
============================

Right now, this is just a proof of concept which decodes Base-64 encoded
`SEQUENCE` objects and pipes them through OpenSSL's `asn1parse` with some
usability improvements like automatically diving into `appl` entries and
formatting hex dumps producing an output that mimics `hd`.

In the future, I plan on having an editor, native java codec and insertion
points for the _Scanner_ module to use.

Building
--------

Execute `ant`, and you'll have the plugin ready in `burp-asn1.jar`

Dependencies
------------

 - JDK 1.7+ (tested on OpenJDK 8, Debian/Ubuntu package: `openjdk-8-jdk`)
 - Apache ANT (Debian/Ubuntu package: `ant`)
 - OpenSSL command line utilities (more specifically `asn1parse(1SSL)`, Debian/Ubuntu package: `openssl`)

License
-------

The whole project is available under MIT license, see `LICENSE.txt`,
except for a subset of the [Apache Commons IO][1], which is available under
the Apache 2.0 license, see the header comments of these files for more
information regarding this.

  [1]: https://commons.apache.org/proper/commons-io/
