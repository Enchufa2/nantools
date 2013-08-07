#!/usr/bin/env python
# coding=UTF-8
# Autor: Iñaki Úcar Marqués
# Año: 2012

import argparse
from pcapy import open_offline

class PktDumper:
	def __init__(self, infile, outfile, pkts):
		self.infile = open_offline(infile)
		self.outfile = self.infile.dump_open(outfile)
		self.pkts = self._parse(pkts)
		self._next = 0
		self._pos = 0
		self._stop = len(self.pkts)
	
	def _parse(self, args):
		pkts = []
		for arg in args:
			if '-' not in arg:
				pkts.append(int(arg))
			else:
				a, b = arg.split('-')
				a = int(a)
				b = int(b)
				pkts.extend(range(min(a, b), max(a, b)+1))
		return sorted(list(set(pkts)))
	
	def _handler(self, header, data):
		self._pos += 1
		if self._pos == self.pkts[self._next]:
			self.outfile.dump(header, data)
			self._next += 1
			if self._next == self._stop:
				raise Exception
	
	def run(self):
		try:
			self.infile.loop(-1, self._handler)
		except:
			pass

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Extrae paquetes individuales y rangos de paquetes de una traza por número de paquete. Por ejemplo, "3 5-7 10" extrae los paquetes 3, 5, 6, 7 y 10.')
	parser.add_argument('-r', dest='infile', required=True, help='PCAP input file')
	parser.add_argument('-w', dest='outfile', required=True, help='PCAP output file')
	parser.add_argument('-p', dest='pkts', required=True, nargs='+', help='packets to extract')
	args = parser.parse_args()
	PktDumper(args.infile, args.outfile, args.pkts).run()
