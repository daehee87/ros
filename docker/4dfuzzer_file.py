import hashlib
import socket
import traceback
import sys
import random
from crccheck.crc import Crcc16Mcrf4xx
import time
import curses
import os

msgid_list = ['110', '373', '69', '138', '117', '43', '258', '251', '330', '51', '283', '50', '109', '126', '44', '11', '84', '23', '40', '400', '147', '132', '75', '121', '144', '149', '340', '139', '41', '390', '268', '106', '73', '412', '65', '333', '45', '102', '4', '47', '233', '119', '82', '288', '70', '39', '107', '246', '122', '247', '254', '250', '253', '282', '334', '76', '115', '21', '20', '113', '331', '48', '332', '350', '77', '86', '114', '0']
msgid_crc = {'110': '84', '373': '117', '69': '243', '138': '109', '117': '128', '43': '132', '258': '187', '251': '170', '330': '23', '51': '196', '283': '74', '50': '78', '109': '185', '126': '220', '44': '221', '11': '89', '84': '143', '23': '168', '40': '230', '400': '110', '147': '154', '132': '85', '75': '158', '121': '237', '144': '127', '149': '200', '340': '99', '139': '168', '41': '28', '390': '156', '268': '14', '106': '138', '73': '38', '412': '33', '65': '118', '333': '231', '45': '232', '102': '158', '4': '237', '47': '153', '233': '35', '119': '116', '82': '49', '288': '20', '70': '124', '39': '254', '107': '108', '246': '184', '122': '203', '247': '81', '254': '46', '250': '49', '253': '83', '282': '123', '334': '72', '76': '152', '115': '4', '21': '159', '20': '214', '113': '124', '331': '91', '48': '41', '332': '236', '350': '232', '77': '143', '86': '5', '114': '237', '0': '50'}
msgid_length_min = {'110': '254', '373': '42', '69': '11', '138': '36', '117': '6', '43': '2', '258': '32', '251': '18', '330': '158', '51': '4', '283': '144', '50': '37', '109': '9', '126': '79', '44': '4', '11': '6', '84': '53', '23': '23', '40': '4', '400': '254', '147': '36', '132': '14', '75': '35', '121': '2', '144': '93', '149': '30', '340': '70', '139': '43', '41': '4', '390': '238', '268': '4', '106': '44', '73': '37', '412': '6', '65': '42', '333': '109', '45': '2', '102': '32', '4': '14', '47': '3', '233': '182', '119': '12', '82': '39', '288': '23', '70': '18', '39': '37', '107': '64', '246': '38', '122': '2', '247': '19', '254': '9', '250': '30', '253': '51', '282': '35', '334': '10', '76': '33', '115': '64', '21': '2', '20': '20', '113': '36', '331': '230', '48': '13', '332': '239', '350': '20', '77': '3', '86': '53', '114': '44', '0': '9'}
msgid_length_max = {'110': '254', '373': '42', '69': '18', '138': '120', '117': '6', '43': '3', '258': '232', '251': '18', '330': '167', '51': '5', '283': '144', '50': '37', '109': '9', '126': '79', '44': '5', '11': '6', '84': '53', '23': '23', '40': '5', '400': '254', '147': '54', '132': '39', '75': '35', '121': '2', '144': '93', '149': '60', '340': '70', '139': '43', '41': '4', '390': '238', '268': '4', '106': '44', '73': '38', '412': '6', '65': '42', '333': '109', '45': '3', '102': '117', '4': '14', '47': '4', '233': '182', '119': '12', '82': '51', '288': '23', '70': '38', '39': '38', '107': '65', '246': '38', '122': '2', '247': '19', '254': '9', '250': '30', '253': '54', '282': '35', '334': '10', '76': '33', '115': '64', '21': '2', '20': '20', '113': '39', '331': '232', '48': '21', '332': '239', '350': '252', '77': '10', '86': '53', '114': '44', '0': '9'}


def random_byte_gen(size):
    return ''. join ([random.choice ('0123456789abcdef') for x in range (2*size)])


def calculate_length(payload):
    return format(len(payload)//2 ,'02x')

def packetGenerator(msgid,len,seq):
    global msgid_crc
    payload = random_byte_gen(len)
    stx = "fd"
    incFLAG = "00"
    cmpFLAG = "00"
    compID = str(format(random.randint(0,255),"02x"))
    sysID = str(format(random.randint(0,255),"02x"))
    magic = format(int(msgid_crc[msgid]),'02x')
    msgid = format(int(msgid),'06x')
    msgid = msgid[-2:]+msgid[-4:-2]+msgid[0:2]
    length = calculate_length(payload)
    seq = format(seq,'02x')
    packet = length+incFLAG+cmpFLAG+seq+sysID+compID+msgid+payload
    crc = Crcc16Mcrf4xx.calc(bytearray.fromhex(packet+magic))
    crc = str(format(crc,'04x'))
    crc = [crc[-2:], crc[0:2]]
    packet += crc[0]+crc[1]
    return stx+packet

seed_folder = sys.argv[1]
def save_packet(packet, msgid):
    global seed_folder
    filename = hashlib.md5(packet.encode('utf-8')).hexdigest()

    with open(seed_folder + '/' + filename + "_msgID" + msgid, 'wb') as f:
        p = bytes.fromhex(packet)
        f.write( p )
        f.close()

def packetSender(msgid=0, iteration=1):
    global seed_folder
    global sock,ip,port,stdscr
    global msgid_length_min, msgid_length_max, msgid_list

    count = 0
    seq = 0

    while True:
        for msgid in msgid_list:
            for len in range(int(msgid_length_min[msgid]), int(msgid_length_max[msgid])+1):
                for _ in range(iteration):
                    start = time.time()
                    # for seq in range(255):
                    packet = packetGenerator(msgid,len,seq)
                    #sock.sendto(bytes.fromhex(packet),(ip,port))
                    count += 1
                    if seq == 255:
                        seq = 0
                    else:
                        seq +=1
                    
                    save_packet(packet, msgid) #added 
                    #data, addr = sock.recvfrom(4096)
                    time.sleep(0.2)

                    if count % 1000 == 0:
                        print('Packet generator running... %d'.format(count))
                    if count % 100000 == 0:
                        print('Cleanup corpus...')
                        os.system('rm -rf %s/*'.format(seed_folder))
        
def OnFuzz():
    packetSender()

if __name__ == '__main__':   
    global mode, runtime
    runtime = time.time()
    OnFuzz()
