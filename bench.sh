#!/bin/bash
set -x

time env ITER=1000 ./testspawn true
time env ITER=1000 ./testfork true
time env ITER=1000 JUNKBYTES=$((1024*1024*200)) ./testspawn true
time env ITER=1000 JUNKBYTES=$((1024*1024*200)) ./testfork true
