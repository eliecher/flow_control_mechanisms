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

global mac, q, do, tosend, s
s: socket.socket
mac: int
q: Queue
do: bool


def listener():
    global do
    while do:
        try:
            packet = s.recv(1024)
        except socket.timeout:
            pass
        else:
            q.put(BitArray(packet))


def sender(*args): print('inside sender')


def showsummary(numpackets, packetssent, goodacks, corruptedacks, wrongseqacks, starttime, endtime, dataperpacket):
    timetaken = ((endtime-starttime)//1000000)/1000
    totalacks = goodacks+corruptedacks+wrongseqacks
    print("")
    print("time taken:", timetaken, "s")
    print("data transferred:", (dataperpacket*numpackets)//1024, "kB")
    print("packets made:", numpackets)
    print("packets sent:", packetssent)
    print("acks received:", totalacks)
    print("good acks:", goodacks, "(", "%.3f" %
          ((goodacks/totalacks)*100), "%)")
    print("out of order acks:", wrongseqacks,
          "(", "%.3f" % ((wrongseqacks/totalacks)*100), "%)")
    print("corrupted acks:", corruptedacks, "(", "%.3f" %
          ((corruptedacks/totalacks)*100), "%)")
    print("effective throughput:", "%.4f" %
          (dataperpacket*numpackets*8/timetaken), "bits/sec")
    print("")


def STWT(packets: list, rmac):
    packetssent = 0
    dataperpacket = len(packets[0])
    goodacks = 0
    wrongseqacks = 0
    corruptedacks = 0
    numpackets = len(packets)
    lastacktime = 0
    starttime = time_ns()
    Sn = 0
    cansend = True
    store = [None, None]
    timer = None
    while packets:
        if cansend:
            data: bytes = packets[0]
            store[Sn] = data
            sendPacket(makeDATA(Sn, rmac, mac, data))
            packetssent += 1
            timer = time_ns()
            Sn ^= 1
            cansend = False
        if not q.empty():
            ack = q.get()
            if not corrupted(ack) and isFresh(ack):
                (ackNo, _, _) = readHeader(ack)
                if ackNo == Sn:
                    timer = None
                    store[Sn ^ 1] = None
                    cansend = True
                    packets.pop(0)
                    goodacks += 1
                    lastacktime = getTimeStamp(ack)
                else:
                    wrongseqacks += 1
            else:
                corruptedacks += 1
        if timer is not None:
            if time_ns()-timer > 80e6:
                timer = time_ns()
                sendPacket(makeDATA(Sn ^ 1, rmac, mac, data))
                packetssent += 1
    sendPacket(makeEND(rmac, mac))
    showsummary(numpackets, packetssent, goodacks, corruptedacks,
                wrongseqacks, starttime, lastacktime, dataperpacket)


def GOBN(packets: list, rmac):
    packetssent = 0
    dataperpacket = len(packets[0])
    goodacks = 0
    wrongseqacks = 0
    corruptedacks = 0
    numpackets = len(packets)
    lastacktime = 0
    starttime = time_ns()
    lim = 1 << 4  # 16
    Sw = lim-1  # 15
    mask = Sw  # 1111
    Sf = 0
    Sn = 0
    store = [None]*lim
    timer = None

    def windfull():
        tSn = Sn
        if tSn < Sf:
            tSn += lim
        return tSn-Sf >= Sw

    def inwind(num):
        tSn = Sn
        if tSn < Sf:
            tSn += lim
        if num < Sf:
            num += lim
        return num > Sf and num <= tSn

    while packets or not Sf == Sn:
        if packets and not windfull():
            store[Sn] = packets.pop(0)
            sendPacket(makeDATA(Sn, rmac, mac, store[Sn]))
            packetssent += 1
            Sn = (Sn + 1) & mask
        if Sf != Sn and timer is None:
            timer = time_ns()
        if not q.empty():
            ack = q.get()
            if not corrupted(ack) and isFresh(ack):
                (ackNo, _, _) = readHeader(ack)
                if inwind(ackNo):
                    goodacks += 1
                    while Sf != ackNo:
                        store[Sf] = None
                        lastacktime = getTimeStamp(ack)
                        Sf = (Sf+1) & mask
                    timer = None
                else:
                    wrongseqacks += 1
            else:
                corruptedacks += 1
        if timer is not None:
            if time_ns()-timer > 100e6:
                temp = Sf
                while temp != Sn:
                    sendPacket(makeDATA(temp, rmac, mac, store[temp]))
                    packetssent += 1
                    temp = (temp+1) & mask
                timer = time_ns()

    sendPacket(makeEND(rmac, mac))
    showsummary(numpackets, packetssent, goodacks, corruptedacks,
                wrongseqacks, starttime, lastacktime, dataperpacket)


def SRARQ(packets: list, rmac):
    packetssent = 0
    dataperpacket = len(packets[0])
    timeout = 300e6+2*dataperpacket*1e6
    goodacks = 0
    wrongseqacks = 0
    corruptedacks = 0
    numpackets = len(packets)
    lastacktime = 0
    starttime = time_ns()
    lim = 1 << 5
    Sw = lim >> 1
    mask = lim-1
    Sf = 0
    Sn = 0
    store = [None]*lim
    timer = [0]*lim

    def windfull():
        tSn = Sn
        if tSn < Sf:
            tSn += lim
        return tSn-Sf >= Sw

    def inwind(num):
        tSn = Sn
        if tSn < Sf:
            tSn += lim
        if num < Sf:
            num += lim
        return num >= Sf and num <= tSn

    while packets or not Sf == Sn:
        if packets and not windfull():
            store[Sn] = packets.pop(0)
            sendPacket(makeDATA(Sn, rmac, mac, store[Sn]))
            #print('sent',Sn)
            packetssent += 1
            timer[Sn] = time_ns()
            Sn = (Sn + 1) & mask
        if not q.empty():
            #print('q not empty')
            ack = q.get()
            if not corrupted(ack) and isFresh(ack):
                isNak: bool = (getpackettype(ack) == packet_type.NAK)
                ackNo: int = getseqnum(ack)
                #print('got',ackNo)
                if inwind(ackNo):
                    goodacks += 1
                    while Sf != ackNo:
                        store[Sf] = None
                        timer[Sf] = 0
                        lastacktime = getTimeStamp(ack)
                        Sf = (Sf+1) & mask
                    if isNak and ackNo != Sn:
                        sendPacket(makeDATA(ackNo, rmac, mac, store[ackNo]))
                        timer[ackNo] = time_ns()
                        packetssent += 1
                else:
                        wrongseqacks += 1
            else:
                #print('ack corrupted')
                corruptedacks += 1
        for i in range(Sf,Sf+Sw):
            i&=mask
            if timer[i]==0:break
            if time_ns()-timer[i] > timeout:
                timer[i] = time_ns()
                sendPacket(makeDATA(i, rmac, mac, store[i]))
                #print('resent',i)
                packetssent += 1

    sendPacket(makeEND(rmac, mac))
    showsummary(numpackets, packetssent, goodacks, corruptedacks,
                wrongseqacks, starttime, lastacktime, dataperpacket)


def RTT(rmac: int):
    q.queue.clear()
    sendPacket(makeEND(rmac, mac))
    while q.empty():
        pass
    timestamp = time_ns()
    sendPacket(makeEND(rmac, mac))
    timediff = timestamp-getTimeStamp(q.get())
    print("Transmission time:", timediff, "ns")


def makepackets(file: BufferedReader, size):
    pckts = []
    while True:
        d = file.read(size)
        if not d:
            return pckts
        pckts.append(d)


def sendPacket(pckt: BitArray):
    s.sendto(pckt.bytes, ("localhost", 5000))


def ui():
    global tosend, do
    while do:
        comm = input().strip()
        if comm[0] == 'q':
            do = False
        elif comm[0] == 's':
            try:
                a, b, fname, d = comm.split()
                to = int(b, 16)
                dataperpacket = int(d)
            except ValueError:
                print("Insufficient data")
            except:
                print("Error")
            else:
                try:
                    f = open(fname, "rb")
                except FileNotFoundError:
                    print("Could not find file to send")
                else:
                    packets = makepackets(f, dataperpacket)
                    f.close()
                    q.queue.clear()
                    sendPacket(makeBEGIN(to, mac))
                    sleep(0.08)
                    if not q.empty():
                        pckt: BitArray = q.get()
                        if getpackettype(pckt) == packet_type.BEGIN:
                            sender(packets, to)
                    else:
                        print('not sending as no BEGIN received')
                    q.queue.clear()
        elif comm[0] == 'r':
            try:
                a, b = comm.split()
            except:
                print("Specify Receiver mac")
            else:
                RTT(int(b, 16))


def init():
    global mac, s, q, sender, do, tosend
    mac = int(input('MAC :'), 16)
    port = int(input('PORT:'))
    print()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('localhost', port))
    s.settimeout(1)
    q = Queue(maxsize=100)
    sender = eval(sys.argv[1])
    do = True


def main():
    init()
    lis = threading.Thread(target=listener, name="listener")
    lis.start()
    ui()
    lis.join()
    global s
    s.close()


if __name__ == '__main__':
    main()
