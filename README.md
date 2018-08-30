# Travel Card Applet

This prototype Travel Card applet is a free and open source implementation of the Travel Card (MTS7) in JavaCard. It based on a PGP applet called SmartPGP which is developed by the french cyber-security authority ANSSI.

## Features

The following features are implemented at the applet level, but some of them depend on underlying hardware support and available (non-)volatile memory resources:

- RSA with 2048 bits modulus and ECC with NIST curve P-256 for authentication;
- On-board key generation and external private key import;
- Multiple MTBs (up to 1 kB each);
- Command and response chaining;
- Extended length APDUs.

## Default values

The SmartPGP applet is configured with the following default values:

- NIST P-256 for key generation
- Extended length APDUs disabled

These values can be changed by modifying default values in the code (see the Constants.java class).

## Compliance with Travel Card specification

The Travel Card applet implements the complete MTS7 specification, except the following features:

- Secure Messaging;
- Specification of algorithm for key generation using a Control Reference Template. Currently, the applet generates the type of keys set as default in the Constants.java class.

# Build and installation instructions

## Prerequisites

- JavaCard Development Kit 3.0.4 (or above) from
  [Oracle website](http://www.oracle.com/technetwork/java/embedded/javacard/downloads/index.html);
- The `ant` tool 1.9.4 (or above) from your Linux distribution or from [Apache Ant project website](http://ant.apache.org/); 
- A device compliant with JavaCard 3.0.4 (or above) with enough available resources to hold the code (approximately 23 kB of non-volatile memory), persistent data (approximately 10 kB of non-volatile memory) and volatile data (approximately 2 kB of RAM).

## Reducing flash and/or RAM consumption

The applet allocates all its data structures to their maximal size at installation to avoid as much as possible runtime errors caused by memory allocation failure. If your device does not have enough flash and/or RAM available, or if you plan not to use some features (e.g. multiple MTBs), you can adjust the applet to reduce its resource consumption by tweaking the following variables:

- `Constants.INTERNAL_BUFFER_MAX_LENGTH`: the size in bytes of the internal RAM buffer used for input/output chaining. Chaining is especially used in case of long commands and responses such as those involved in private key import and certificate import/export.
  
- `Constants.EXTENDED_CAPABILITIES`, bytes 5 and 6: the maximal size in bytes of a certificate associated to a key. Following the OpenPGP card specification, a certificate can be stored for each of the three keys. In SmartPGP, a fourth certificate is stored for secure messaging.


## Building the CAP file
- Copy the `javacard.properties.example` file to a file named
  `javacard.properties`;

- Edit the `javacard.properties` file and set the path of your JavaCard Development Kit;
- Edit the `build.xml` file and to reflect your assigned PID in the `APPLET_AID`;
- Execute `ant` with no parameter will produce the CAP file in `build/travelcard.cap`.


## Installing the CAP file

The CAP file installation depends on your device, so you have to refer to the instructions given by your device manufacturer. Most open cards relying on Global Platform with default keys are supported by [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro).

Be careful to use a valid AID according to the Travel Card specification (see section 4.2.1) for each card.
