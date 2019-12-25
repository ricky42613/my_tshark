#! /bin/bash
.PHONY:clean

default:
	gcc myshark.c -o myshark -lpcap

clean:
	rm server client 