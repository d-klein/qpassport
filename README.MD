About
------
------

QPassport Reader is a simple (and somewhat crude) Linux/Unix
Application to read Datagroup 1 (DG1, digitally stored 
Machine Readable Zone) and Datagroup 2 (DG2, Digitally stored portrait)
by executing Basic Access Control (BAC) as defined in ICAO 9303.

There are other libraries and tools that already implement BAC (such
as RFIDIOT), but I wanted to implement this myself as an exercise
to get familiar with secure messaging, the file structure, 
access mechanisms, and ISO 7816-4 of passports.

The sourcecode (the card part, not the messy gui part) might also
help you to get some overview on how all of the above work together.
At least I hope so :-)

Installation
------------
------------

Only Linux is tested. Windows and OS X should work in theory,
but are untested right now.

Linux Installation:

The following packages must be installed first (package names
are from Ubuntu, but should be named similar in other
distros):

- pcsc-tools
- python (2)
- python-crypto
- python-qt4-dev
- python-pyscard

Connect your smartcard reader to your system. You can
verify that the smartcard reader and the pcsc-interface 
are working by putting a card on the reader and calling

    pcsc_scan

Last, unzip qpassport.zip to a folder, say smartcard and

    cd smartcard
    python main.py

Note that to prove physical posession of the passport, you 
will need to enter the Machine Readable Zone (MRZ) to get
access to the digitally stored information.