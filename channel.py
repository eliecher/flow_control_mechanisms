#! /bin/python3
from os import error, wait
from queue import Queue
import threading
import socket
import random
from bitstring import BitArray
from packet import *
import time

global configs, s, do
global pushq, getq, delayq
do: bool


def listener():
    global do
    pushq, s
    while do:
        try:
            pckt = s.recv(1024)
        except socket.timeout:
            pass
        else:
            # print('got a packet')
            getq.put(BitArray(pckt))


def injectBitError(pckt: BitArray):
    pos = 136
    while pos in {136, 137, 138, 139}:
        pos = random.randint(0, len(pckt) - 1)
    pckt.invert(pos)


def errormaker():
    global do
    global pushq, getq, delayq
    while do:
        if getq.empty():
            time.sleep(0.01)
            continue
        pckt = getq.get()
        ptype = getpackettype(pckt)
        if ptype != packet_type.BEGIN and ptype != packet_type.END:
            if random.choices((True, False), weights=(1, 99), k=1)[0]:
                pass
            else:
                if random.choices((True, False), weights=(10, 90), k=1)[0]:
                    injectBitError(pckt)
                if random.choices((True, False), weights=(10, 90), k=1)[0]:
                    delayq.put(pckt)
                else:
                    pushq.put(pckt)
        else:
            pushq.put(pckt)
    while not getq.empty():
        pushq.put(getq.get())


def delayer():
    global do
    delayq, pushq
    while do:
        if delayq.empty():
            time.sleep(0.02)
            continue
        pckt = delayq.get()
        time.sleep(0.001 * random.randint(1, 5))
        pushq.put(pckt)
    while not delayq.empty():
        pushq.put(delayq.get())


def sender():
    global do
    global configs, pushq, s
    while do:
        if pushq.empty():
            time.sleep(0.01)
            continue
        pckt: BitArray = pushq.get()
        dstmac = getdestination(pckt)
        if dstmac in configs:
            # print('sent to',dstmac)
            s.sendto(pckt.bytes, ("localhost", configs[dstmac]))
    while not pushq.empty():
        pckt: BitArray = pushq.get()
        dstmac = getdestination(pckt)
        if dstmac in configs:
            s.sendto(pckt.bytes, ("localhost", configs[dstmac]))


def ui():
    global configs, do
    freeports = {
        5001,
        5002,
        5003,
        5004,
        5005,
        5006,
        5007,
        5008,
        5008,
        5010,
        5011,
        5012,
        5013,
        5014,
        5015,
        5016,
    }
    while do:
        c = input().strip()
        try:
            comm, mac = c.split()
        except ValueError:
            comm = c
        else:
            mac = int(mac, 16)
        if comm[0] == "c" and mac in configs:
            print("mac already exists [", configs[mac], "]")
        elif comm[0] == "d" and mac in configs:
            x = configs.pop(mac)
            freeports.add(x)
            print(mac, "disconnected. Port", x, "freed")
        elif comm[0] == "c":
            if freeports.__len__ == 0:
                print("No more connections possible")
            else:
                x = freeports.pop()
                configs[mac] = x
                print("port", x, "assigned to mac", mac)
        elif comm[0] == "s":
            print(configs)
        elif comm[0] == "q":
            do = False


def main():
    # Opening and binding socket
    global s, do
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("localhost", 5000))
    s.settimeout(1)
    do = True
    # Initialising
    global pushq, getq, delayq, configs
    configs = {}
    getq = Queue(maxsize=100)
    delayq = Queue(maxsize=20)
    pushq = Queue(maxsize=100)
    # Threads
    listening = threading.Thread(target=listener, name="listener")
    errort = threading.Thread(target=errormaker, name="Errormaker")
    delayt = threading.Thread(target=delayer, name="Delayer")
    sendt = threading.Thread(target=sender, name="Sender")
    # Starting threads
    listening.start()
    errort.start()
    delayt.start()
    sendt.start()
    ui()
    # Joining threads
    listening.join()
    errort.join()
    delayt.join()
    sendt.join()
    s.close()


if __name__ == "__main__":
    main()
