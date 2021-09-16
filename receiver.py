#! /bin/python3
import sys
import os
import uuid
from genericpath import isdir
from io import BufferedReader
from queue import Queue
import socket
import threading
from typing import Deque
from bitstring import BitArray, pack
from packet import *
from time import sleep, time_ns


def receiver(*args):
    print('receiver dummy')


global do, mac, q, s
mac: int
do: bool
q: Queue
s: socket.socket


def listener():
    global q, do
    while do:
        try:
            packet = s.recv(1024)
        except socket.timeout:
            pass
        else:
            q.put(BitArray(packet))


def RTT(senmac: int):
    global q
    q.queue.clear()
    sendPacket(makeBEGIN(senmac, mac))
    while q.empty():
        pass
    timestamp = time_ns()
    timediff = timestamp - getTimeStamp(q.get())
    print("Transmission time:", timediff, "ns")


def rmode():
    global do, q
    while do:
        if q.empty():
            sleep(0.01)
            continue
        packet: BitArray = q.get()
        (_, _, senmac) = readHeader(packet)
        if getpackettype(packet) == packet_type.BEGIN:
            receiver(senmac)
        elif getpackettype(packet) == packet_type.END:
            RTT(senmac)


def showsummary(firstpackettime, lastpackettime, datatransfered, packetsreceived, erroneouspackets, goodpackets, wrongseqpackets, ackssent):
    timetaken = (lastpackettime-firstpackettime)//1000000
    print("")
    print("time taken:", timetaken/1000, "s")
    print("data transferred:", datatransfered//1024, "kB")
    print("packets received:", packetsreceived)
    print("Good packets: ", goodpackets, "(", "%.3f" %
          ((goodpackets/packetsreceived)*100), "%)")
    print("erroneous packets: ", erroneouspackets, "(", "%.3f" %
          ((erroneouspackets/packetsreceived)*100), "%)")
    print("wrong sequenced packets: ", wrongseqpackets, "(", "%.3f" %
          ((wrongseqpackets/packetsreceived)*100), "%)")
    print("ACKs sent:", ackssent)
    print("effective throughput:", "%.4f" %
          (datatransfered*8000/timetaken), "bits/sec")
    print("")


def STWT(senmac: int):
    packetsreceived = 0
    erroneouspackets = 0
    wrongseqpackets = 0
    datatransfered = 0
    firstpackettime = 0
    lastacktime = 0
    goodpackets = 0
    ackssent = 0
    got = False
    data = bytearray()
    Rn = 0
    sendPacket(makeBEGIN(senmac, mac))
    while True:
        while q.empty():
            sleep(0.01)
        packet: BitArray = q.get()
        packetsreceived += 1
        if corrupted(packet):
            erroneouspackets += 1
            continue
        type = getpackettype(packet)
        if type == packet_type.END:
            break
        if not isFresh(packet):
            continue
        seqNo: int = getseqnum(packet)
        if seqNo == Rn:
            packetdata = extractData(packet)
            datatransfered += len(packetdata)
            data += packetdata
            goodpackets += 1
            Rn ^= 1
        else:
            wrongseqpackets += 1
        ack = makeACK(Rn, senmac, mac)
        sendPacket(ack)
        lastacktime = getTimeStamp(ack)
        ackssent += 1
        if not got:
            firstpackettime = getTimeStamp(packet)
        got = True
    q.queue.clear()
    showsummary(firstpackettime, lastacktime, datatransfered,
                packetsreceived, erroneouspackets, goodpackets, wrongseqpackets, ackssent)


def GOBN(senmac: int):
    q.queue.clear()
    packetsreceived = 0
    erroneouspackets = 0
    goodpackets = 0
    wrongseqpackets = 0
    datatransfered = 0
    firstpackettime = 0
    lastacktime = 0
    ackssent = 0
    mask = (1 << 4)-1  # mask 1111
    got = False
    data = bytearray()
    Rn = 0
    sendPacket(makeBEGIN(senmac, mac))
    while True:
        while q.empty():
            sleep(0.01)
        packet: BitArray = q.get()
        packetsreceived += 1
        if corrupted(packet):
            erroneouspackets += 1
            continue
        type = getpackettype(packet)
        if type == packet_type.END:
            break
        if not isFresh(packet):
            continue
        seqNo: int = getseqnum(packet)
        if seqNo == Rn:
            packetdata = extractData(packet)
            datatransfered += len(packetdata)
            data += packetdata
            goodpackets += 1
            Rn = (Rn+1) & mask
            ack = makeACK(Rn, senmac, mac)
            sendPacket(ack)
            lastacktime = getTimeStamp(ack)
            ackssent += 1
        else:
            wrongseqpackets += 1
        if not got:
            firstpackettime = getTimeStamp(packet)
        got = True
    q.queue.clear()
    showsummary(firstpackettime, lastacktime, datatransfered,
                packetsreceived, erroneouspackets, goodpackets, wrongseqpackets, ackssent)


def SRARQ(senmac: int):
    packetsreceived = 0
    erroneouspackets = 0
    goodpackets = 0
    wrongseqpackets = 0
    datatransfered = 0
    firstpackettime = 0
    lastacktime = 0
    ackssent = 0
    lim = 1 << 5  # 16
    Rw = lim >> 1  # 8
    mask = lim-1  # 1111
    got = False
    data = bytearray()
    Rn = 0
    naksent = False
    ackneeded = False
    bad = False
    sendPacket(makeBEGIN(senmac, mac))
    marked = [False]*lim
    stored = {}

    def inwindow(num):
        if num < Rn:
            num += lim
        return num < Rn+Rw

    while True:
        while q.empty():
            sleep(0.01)
        bad = False
        packet: BitArray = q.get()
        packetsreceived += 1
        if corrupted(packet):
            bad = True
            erroneouspackets += 1
        else:
            type = getpackettype(packet)
            if type == packet_type.END:
                break
        if not isFresh(packet):
            bad = True
        if bad:
            if not naksent:
                sendPacket(makeNAK(Rn, senmac, mac))
                #print('nak',Rn)
                ackssent += 1
                naksent = True
            continue
        seqNo: int = getseqnum(packet)
        #print('got',seqNo)
        if seqNo != Rn:
            wrongseqpackets += 1
            if not naksent or ((seqNo+1) & mask) == Rn:
                sendPacket(makeNAK(Rn, senmac, mac))
                #print('nak',Rn)
                ackssent += 1
                naksent = True
        if inwindow(seqNo) and not marked[seqNo]:
            # #print('extractable',seqNo)
            marked[seqNo] = True
            stored[seqNo] = extractData(packet)
        while marked[Rn]:
            fdata = stored[Rn]
            datatransfered += len(fdata)
            data += fdata
            marked[Rn] = False
            stored.pop(Rn)
            Rn = (Rn+1) & mask
            ackneeded = True
        if ackneeded:
            goodpackets += 1
            ack = makeACK(Rn, senmac, mac)
            sendPacket(ack)
            #print('ack sent',Rn)
            ackssent += 1
            lastacktime = getTimeStamp(ack)
            ackssent += 1
            ackneeded = False
            naksent = False
        if not got:
            firstpackettime = getTimeStamp(packet)
        got = True
    q.queue.clear()
    showsummary(firstpackettime, lastacktime, datatransfered,
                packetsreceived, erroneouspackets, goodpackets, wrongseqpackets, ackssent)


def sendPacket(pckt: BitArray):
    s.sendto(pckt.bytes, ("localhost", 5000))


def ui():
    global do
    while do:
        comm = input().strip()
        if comm[0] == 'q':
            do = False


def init():
    global mac, s, q, receiver, do
    mac = int(input('MAC :'), 16)
    port = int(input('PORT:'))
    print()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', port))
    s.settimeout(1)
    q = Queue(maxsize=100)
    receiver = eval(sys.argv[1])
    do = True


def main():
    init()
    lis = threading.Thread(target=listener, name="listener")
    rec = threading.Thread(target=rmode, name="receiver")
    lis.start()
    rec.start()
    ui()
    rec.join()
    lis.join()
    global s
    s.close()


if __name__ == '__main__':
    main()
