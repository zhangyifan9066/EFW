#!/bin/bash

tcpdump -i en0 -w $1 &

cnt=0
while [[ ${cnt} -lt 20 ]];
do
  #statements
  arp -d -a
  sleep 10;
  discoveryutil mdnsflushcache
  sleep 10;
  cnt=`expr ${cnt}+1`
done

killall tcpdump
