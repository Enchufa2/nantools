#!/usr/bin/env python
# coding=UTF-8
# Autor: Iñaki Úcar Marqués

import argparse
from pcapy import open_offline

class PktDumper:
	def __init__(self, dups, infile, outfile):
		self.dups = open(dups)
		self.infile = open_offline(infile)
		self.outfile = self.infile.dump_open(outfile)
		self.deleted = self.infile.dump_open(outfile + '_deleted.cap')
		self._next = 0
		self._pos = 0
	
	def _getNext(self):
		line = self.dups.readline().split()
		if len(line) > 0:
			self._next = int(line[0])
	
	def _handler(self, header, data):
		self._pos += 1
		if self._pos == self._next:
			self.deleted.dump(header, data)
			self._getNext()
		else:
			self.outfile.dump(header, data)
	
	def run(self):
		self._getNext()
		self.infile.loop(-1, self._handler)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Removes duplicates from a PCAP file.')
	parser.add_argument('-f', dest='dups', required=True, help='infodups output')
	parser.add_argument('-r', dest='infile', required=True, help='PCAP input file')
	parser.add_argument('-w', dest='outfile', required=True, help='PCAP output file')
	args = parser.parse_args()
	PktDumper(args.dups, args.infile, args.outfile).run()
