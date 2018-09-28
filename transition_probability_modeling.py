from collections import Counter
from time import sleep
from os import sys
import numpy as np

def TPM_r(a,a_packet,block_size, fw,total_len):
    #print "a: "+a+"\nlen: "+str(len(a_packet[-1:]))+"\n", a_packet
    list_A = list()
    list_A.append(a)
    fw.write(a+"-")
    if a_packet[0][0] == ".":
        list_A.append(a_packet)
        fw.write(a_packet[0]+"\n")
        return list_A
    seperate_packet = {}

    for temp_packet in a_packet:
        try:
            seperate_packet[temp_packet[0:block_size]].append(temp_packet[block_size:])
        except KeyError:
            #seperate_packet[temp_packet[0:block_size]] = list()
            seperate_packet[temp_packet[0:block_size]] = list()
            seperate_packet[temp_packet[0:block_size]].append(temp_packet[block_size:])
    loop_ctr = len(seperate_packet.keys())
    for key in seperate_packet.keys():
        loop_ctr = loop_ctr -1
        list_A.append(TPM_r(key,seperate_packet[key],block_size,fw,total_len))
        if loop_ctr == 0: break
        if block_size == 2:
            fw.write(" "*int((3*(total_len/2-len(a_packet[0].split(".")[0])/2))))
        elif block_size == 1:
            fw.write(" "*int((2*(total_len-len(a_packet[0].split(".")[0])))))
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
#fr = open("E:/automobile_fuzzing/can_log/sorento/SorentoR.asc.txt", "r")#for sorento
fr = open("E:/automobile_fuzzing/can_log/trace_txt/trace.txt", "r")# for trace_txt
block_size = 1 #1: half byte 2: byte
id_list= {}
seperate_packet = {}
id_index = 3#2 for sorento, 3 for trace.txt
data_index = 5#6 for sorento, 5 for trace.txt
while True:
    line = fr.readline()
    if not line: break
    if line[0] == ";": continue
    split_line = line.split()
    if split_line[0] == "End": break
    data_field = full_data(split_line[data_index:])#6 for sorento

    try:
        id_list[split_line[id_index]].append(data_field)#2 for sorento
    except KeyError:
        id_list[split_line[id_index]] = list()
        id_list[split_line[id_index]].append(data_field)
        seperate_packet[split_line[id_index]] = dict()

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
    #if temp_id != "0260": continue#for testing graph
    fw = open("E:/automobile_fuzzing/can_log/trace_txt/id_tpm/"+temp_id+".txt", "w+")
    #fw = open("E:/automobile_fuzzing/can_log/sorento/id_tpm/"+temp_id+".txt", "w+")
    print ("id : "+temp_id+"\n")
    fw.write("total : "+str(len(id_list[temp_id]))+"\n")
    result = list()
    for key in seperate_packet[temp_id].keys():
        total_len = len(id_list[temp_id][0])
        result = TPM_r(key,seperate_packet[temp_id][key], block_size, fw,total_len)
        print(result)