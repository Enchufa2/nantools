# NaNTools: Network aNalysis Tools

This project wants to be yet another set of network analysis tools. Currently, there are the following tools:

* `infodups` identifies and marks duplicate packets in PCAP files.
* `tseries` computes multiple time series from PCAP files.

## Compilation

You need to install the libpcap library. Then, simply run these commands:

```bash
git clone git@github.com:Enchufa2/nantools.git
cd build
make
```

You can also build specific targets only:

```bash
make infodups
make tseries
```

## Description

### `infodups`

Any network traffic monitoring system, especially port-mirroring schemes, has to deal with a challenging problem: the traffic capturing process almost invariably produces duplicate packets. Some tools like `editcap`, from `wireshark/tshark`, can remove only exact copies of packets. Nevertheless, there are different types of duplicates that don't constitute identical copies in general. For more information about the problem of duplicates, you can read this paper:

> [Coming soon. Pending publication in the _IEEE International Workshop on Measurements & Networking 2013_]

This tool is intended to identify and mark duplicate packets in PCAP files. Here is an execution example with a sliding window of 10 ms:

```
$ ./infodups -i trace.pcap -t 0.01
74349 8 0 1 0 0 0.000873000 0
74401 52 0 1 0 0 0.004262000 0
74421 20 0 1 0 0 0.001023000 0
92561 3 0 1 0 0 0.000645000 0
95486 1 0 0 0 0 0.000009000 0
...
```

Each line belongs to one duplicate pair identified. The first two numbers mean that the packet number 74349 is a duplicate from 8 positions before, etc.

Since searches over a sliding window can be a very heavy task, this tool supports multithreading. For more info and usage notes, run:

```bash
./infodups -h
```

---

### `tseries`

This tool accepts a network trace in PCAP format and a file with one filter per line. Then, it computes the time series corresponding to each filter. These filters can be defined in two different ways: as __BPF filters__ or __net filters__.

#### BPF filters

For example, suppose you want to compute the time series for all TCP traffic coming to the host 192.168.1.1, and all UDP traffic coming from the net 192.168.0.0/16. You should write a file `filters.txt` containing these lines:

```
tcp and dst host 192.168.1.1
udp and src net 192.168
```

Then, `tseries` execution yields something like this:

```
$ ./tseries -i trace.pcap -f filters.txt
0 1338754657325 10262757 8928
1 1338754657325 0 0
0 1338754658325 12159973 10119
1 1338754658325 98 1
0 1338754659325 10509878 8702
1 1338754659325 470 4
0 1338754660325 12402697 10068
1 1338754660325 98 1
...
```

Each line contains:

* the filter identifier (0 for the first filter in the file and so on).
* the timestamp (in milliseconds).
* the number of bytes in the last bucket.
* the number of packets in the last bucket.

#### Net filters

This alternative filtering mode only allows us to define source and/or destination nets and IPs, but it has an efficiency advantage over the BPF equivalent. While filtering with _N_ BPF filters has time cost _O(N)_, net filters improve this to _O(1)_. It can be achieved using a special data structure called __Grid-of-Tries__. This particular implementation was inspired in the following paper:

> V. Srinivasan, G. Varghese, S. Suri, and M. Waldvogel. 1998. __Fast and scalable layer four switching__. _SIGCOMM Comput. Commun. Rev. 28_, 4 (October 1998), 191-202. [DOI: 10.1145/285243.285282](http://doi.acm.org/10.1145/285243.285282)

Here is an example of the net filters syntax:

```
192.168.0.0   255.255.0.0       0.0.0.0       0.0.0.0
192.168.1.1   255.255.255.255   192.168.0.0   255.255.0.0
```

Which can be read as follows:

* All traffic coming from the net 192.168.0.0/16.
* All traffic coming from the IP 192.168.1.1 and going to the net 192.168.0.0/16.

For more info and usage notes, run:

```bash
./tseries -h
```
