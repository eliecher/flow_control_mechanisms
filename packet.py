#! /bin/python3
from functools import partial
from enum import Enum
from time import time, time_ns
from bitstring import BitArray, ConstBitArray, pack
crc_32_div = BitArray("0b100000100110000010001110110110111")
crc_16_div = BitArray("0b11000000000000101")




def CRC_16(data: BitArray):
    syndrome = BitArray(17)
    for i in range(len(data)):
        syndrome <<= 1
        syndrome[16] = data[i]
        if syndrome[0]:
            syndrome ^= crc_16_div
    return syndrome[1:]


def CRC_32(data: BitArray):
    syndrome = BitArray(33)
    for i in range(len(data)):
        syndrome <<= 1
        syndrome[32] = data[i]
        if syndrome[0]:
            syndrome ^= crc_32_div
    return syndrome[1:]


class packet_type(Enum):
    DATA = 1
    BEGIN = 2
    END = 4
    ACK = 8
    NAK = 16


def corrupted(packet: BitArray):
    if not verifyHeader(packet):
        return True
    if packet[168:176].uint == 1:
        return not verifyData(packet)
    return False


def getseqnum(packet: BitArray):
    return packet[0:8].uint


def make_header(pno: int, rmac: int, smac: int, ptype: packet_type, datalen: int):
    pack = BitArray(uint=pno, length=8)
    pack.append(BitArray(uint=rmac, length=48))
    pack.append(BitArray(uint=smac, length=48))
    timestamp = time_ns()
    pack.append(BitArray(uint=timestamp, length=64))
    pack.append(BitArray(uint=ptype.value, length=8))
    pack.append(BitArray(uint=datalen, length=8))
    pack.append(16)
    pack[-16:] = CRC_16(pack)
    return pack


def getpackettype(pckt: BitArray):
    return packet_type(int.from_bytes(pckt[168:176].bytes, byteorder="big"))


def makeDATA(pno: int, rmac: int, smac: int, data: bytes):
    pckt = make_header(pno, rmac, smac, packet_type.DATA, len(data))
    pckt.append(BitArray(data))
    pckt.append(32)
    pckt[-32:] = CRC_32(pckt[200:])
    return pckt


def makeBEGIN(rmac: int, smac: int):
    return make_header(0, rmac, smac, packet_type.BEGIN, 0)


def makeEND(rmac: int, smac: int):
    return make_header(8, rmac, smac, packet_type.END, 0)


def makeACK(pno: int, rmac: int, smac: int):
    return make_header(pno, rmac, smac, packet_type.ACK, 0)


def makeNAK(pno: int, rmac: int, smac: int):
    return make_header(pno, rmac, smac, packet_type.NAK, 0)


def verifyHeader(pckt: BitArray):
    return CRC_16(pckt[:200]).uint == 0


def verifyData(pckt: BitArray):
    return CRC_32(pckt[200:]).uint == 0


def readHeader(pckt: BitArray):
    pno = pckt[0:8].uint
    rmac = pckt[8:56].uint
    smac = pckt[56:104].uint
    return pno, rmac, smac


def getdestination(pckt: BitArray):
    return pckt[8:56].int


def isFresh(pckt: BitArray):
    return time_ns()- pckt[104:168].uint < 1e9


def isVeryFresh(pckt: BitArray):
    timestamp = time_ns()
    return timestamp - pckt[104:168].uint < 5e8


def getTimeStamp(pckt: BitArray):
    return pckt[104:168].uint


def extractData(pckt: BitArray):
    l = pckt[176:184].uint
    return pckt[200:200+8*l].bytes
