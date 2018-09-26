from collections import Counter
from time import sleep

def TPM_r(a,a_packet,block_size):
    #print "a: "+a+"\nlen: "+str(len(a_packet[-1:]))+"\n", a_packet
    list_A = list()
    list_A.append(a)
    if a_packet[0][0] == ".":
        list_A.append(a_packet)
        return list_A
    seperate_packet = {}

    for temp_packet in a_packet:
        try:
            seperate_packet[temp_packet[0:block_size]].append(temp_packet[block_size:])
        except KeyError:
            seperate_packet[temp_packet[0:block_size]] = list()
            seperate_packet[temp_packet[0:block_size]].append(temp_packet[block_size:])

    for key in seperate_packet.keys():
        #print "-- ",key, seperate_packet[key], "\n"
        list_A.append(TPM_r(key,seperate_packet[key],block_size))

    return list_A


def frequency(packet, freq, block_size):#frequency checking
    for i in range(0, len(packet)/block_size):
        if packet[i*block_size:i*block_size + block_size] in freq[i].keys():
            freq[i][packet[i*block_size:i*block_size + block_size]] += 1
        else:
            freq[i][packet[i*block_size:i*block_size + block_size]] = 1


def full_data(line):
    string_data = ""
    for data in line:
        string_data += data

    return string_data

#main
fr = open("E:/automobile_fuzzing/can_log/sorento/SorentoR.asc.txt", "r")
block_size = 2 #1: half byte 2: byte
id_list= {}
seperate_packet = {}

while True:
    line = fr.readline()
    if not line: break
    if line[0] == ";": continue
    split_line = line.split()
    if split_line[0] == "End": break
    data_field = full_data(split_line[6:])

    try:
        id_list[split_line[2]].append(data_field)
    except KeyError:
        id_list[split_line[2]] = list()
        id_list[split_line[2]].append(data_field)
        seperate_packet[split_line[2]] = dict()

for seperate_id in id_list.keys():
    nodup = list(set(id_list[seperate_id]))
    freq = Counter(id_list[seperate_id])
    for temp_packet in nodup:
        try:
            seperate_packet[seperate_id][temp_packet[0:block_size]].append(temp_packet[block_size:]+"."+str(freq[temp_packet]))
        except KeyError:
            seperate_packet[seperate_id][temp_packet[0:block_size]] = list()
            seperate_packet[seperate_id][temp_packet[0:block_size]].append(temp_packet[block_size:]+"."+str(freq[temp_packet]))

for temp_id in seperate_packet.keys():
    print "id : "+temp_id+"\n"
    result = list()
    for key in seperate_packet[temp_id].keys():
        result = TPM_r(key,seperate_packet[temp_id][key], block_size)
        print result
        sleep(3)