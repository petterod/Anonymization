# Anonymization 
Anonymization of IPv4/IPv6/TCP/UDP-packet header logs, web server logs, NetFlow logs and syslogs

The programs in this repository anonymize fields in IPv4/IPv6/TCP/UDP-header logs, web server logs, NetFlow logs and syslogs.

## Bilateral Classification ##

Bilateral Classification groups the TTL or the Hop Limit field as either 0 or 255. TTL or Hop Limit should be specified.
It requires an input text file and an output text file. The text file should be formatted as performed with "FormattingIP", 
which can be found in repository "FormattingPcap". Bilateral Classification as a runnable JAR file is run as such:

java -jar Bilateralclassification.jar TTL/HopLimit input-text-file output-text-file

## Generalization ##

Generalization rounds port number above 49151 to the nearest hundred. The log type (IPv4/IPv6/NetFlow) should be specified.
It requires an input text file and an output text file. The text file should be formatted as performed with "FormattingIP",
which can be found in repository "FormattingPcap". Generalization as a runnable JAR file is run as such:

java -jar Generalization.jar logtype input-text-file output-text-file

## IdentificationGrouping ##

IdentificationGrouping groups Identification values into eight equally large groups. It requires an input text file and an output text file. 
The text file should be formatted as performed with "FormattingIP", which can be found in repository "FormattingPcap". 
IdentificationGrouping as a runnable JAR file is run as such:

java -jar IdentificationGrouping.jar input-text-file output-text-file

## IPTruncationIIR ##

IPTruncationIIR truncates the last octet of an IPv4 address and the last 16 bits of an IPv6 address. 
The log type (IPv4/IPv6/NetFlow/Webserver) should be specified. It requires an input text file and an output text file.
The text file should be formatted as performed with "FormattingIP", which can be found in repository "FormattingPcap". In addition,
it should have inter- and intra-records added, performed with the "AddingRecords" programs for the various log types 
from repository "Validation". IPTrucationIIR as a runnable JAR file is run as such:

java -jar IPTruncationIIR.jar logtype input-text-file output-text-file

## LogHashing ##

LogHashing hashes the Request (URL) field from a web server log or the Message field from a syslog. The log type (Webserver/syslog) 
should be specified. It requires an input text file and an output text file. The text file should be formatted as 
performed with "FormattingWebserver", which can be found in repository "Validation". 
LogHashing as a runnable JAR file is run as such:

java -jar LogHashing.jar logtype input-text-file output-text-file
