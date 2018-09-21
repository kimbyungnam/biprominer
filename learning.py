from collections import Counter
from time import sleep
import sys
import copy

#get rid of duplication
def unduplication(packet):
    nodup = list(set(packet))

    return nodup

#combination of learning phase and labeling phase
def learning_labeling(packet, freq, m_parameter, amount, block_size, fw, n_parameter, transition):
    nodup = copy.copy(packet)
    cell_list = []
    temp_cell_ist = []
    r_parameter = float(n_parameter*amount)/256
    #sys.stderr.write("r"+ str(r_parameter)+"\n")
    fw3 = open("E:/automobile_fuzzing/can_log/trace_txt/test.txt", 'w+')#file writings are just for testing

    while True:# loop until there is no more cell
        cell_len = len(cell_list)
        fw3.write(str(len(packet))+"\n")
        #print str(len(packet)),

        for j in range(0,len(packet)):
            packet_cell = []
            #sys.stderr.write("j1 "+ str(j)+"\t"+packet[j] + "\n")
            check = Counter(packet[j])
            labeled = check[' ']/block_size
            unlabeled = len(packet[j])/block_size - labeled# parameter h

            if unlabeled == 0: continue

            threshold = amount/(m_parameter * unlabeled)
            sys.stderr.write(str(threshold)+" "+str(r_parameter)+"\n")
            fw3.write(str(len(packet[j])) + "\t"+ str(len(packet[j])/block_size)+"\n")

            for i in range(0, len(packet[j]) / block_size):
                if packet[j][i*block_size] == " ": continue
                #sys.stderr.write("i2 "+str(i)+"\t~"+packet[j][i*block_size:i*block_size+block_size]+"~\n")
                #sys.stderr.write(str(packet[j])+"\t~"+packet[j][i*block_size:i*block_size+block_size]+"~\n")
                block = packet[j][i*block_size:i*block_size+block_size]
                if freq[i][block] >= threshold:
                    #sys.stderr.write("3 "+str(freq[i][block])+"\t"+str(threshold)+"\t"+str(i)+"\n")
                    cell = {}
                    cell['START'] = i*block_size#start index
                    cell['END'] = i*block_size + block_size -1#end index
                    cell['value'] = block#cell value
                    #print i, cell['value'], "cell"
                    #print packet[j],
                    #sys.stderr.write("4&&&\n")
                    for t in range(i+1, len(packet[j])/block_size):
                        #sys.stderr.write("--5 " + packet[j][t*block_size:t*block_size+block_size] + "\t"+str(freq[t][packet[j][t*block_size:t*block_size+block_size]]) + " --\n")
                        if freq[t][packet[j][t*block_size:t*block_size+block_size]] >= r_parameter:
                            cell['END'] = t*block_size + block_size - 1
                            cell['value'] += packet[j][t*block_size:t*block_size+block_size]
                            #sys.stderr.write(str(cell['END'])+"\n")
                        else:
                            break

                    for t in range(i-1,-1, -1):
                        #sys.stderr.write("**6 "+packet[j][t*block_size:t*block_size+block_size] + "\t"+str(freq[t][packet[j][t*block_size:t*block_size+block_size]]) +  "**\n")
                        if freq[t][packet[j][t*block_size:t*block_size+block_size]] >= r_parameter:
                            cell['START'] = t*block_size
                            cell['value'] = packet[j][t*block_size:t*block_size+block_size] + cell['value']
                            #sys.stderr.write("7 "+str(cell['START'])+"\n")
                        else:
                            break
                    for key in transition.keys():
                        if key == packet[j]:
                            cell['PROBABILITY'] = float(transition[key])/amount
                            print "tptp", cell['PROBABILITY'], transition[key], amount
                            break
                    packet_cell.append(cell)
                    cell_list.append(cell)
                    #temp_cell_ist.append([packet[j], for_list, cell['PROBABILITY']])

                    packet[j] = packet[j][0:cell['START']]+ " "* len(cell['value']) + packet[j][cell['END']+1:]
                    #print len(packet[j]), packet[j], "\n"
                    #fw.write("START: "+str(cell['START'])+"\tEND: "+str(cell['END'])+"\tvalue: "+str(cell['value'])+"\n")
                    #sys.stderr.write("8 " +packet[j]+"\tdone\n"+str(cell['START'])+"\t"+str(cell['END'])+"\t"+str(cell['value'])+"\n")

        if cell_len == len(cell_list):# check there is new cell creation
            print "all done"
            for i in range(0, len(nodup)):
                fw.write(nodup[i]+"\n")
                if Counter (packet[i])[" "] == 0:
                    fw.write("no cell\n")
                    continue
                for j in range(0, len(nodup[i])):
                    if packet[i][j] == " ":
                        fw.write("*")
                    else:
                        fw.write(" ")
                #print transition
                for j in transition.keys():
                    #print nodup[i]
                    if j == nodup[i]:
                        fw.write("\tTP: "+str(float(transition[j])/amount)+"\n")
                        break
            fw.close()
            break

    return cell_list, packet#for transitional probability model return packet too

#input:integer, size of number
def strtoi(integer, digit):
    result = ""
    for i in range(0, digit):
        if not integer:
            result = "0" + result
            continue
        remainder = integer%2
        result = str(remainder) + result
        integer = integer/2
    if integer:
        return "err: strtoi exceeding digit"

    return result


def full_data(line):#2 base data field
    string_data = ""
    for data in line:
        string_data += strtoi(int(data, 16),8)

    return string_data


def frequency(packet, freq, block_size):#frequency checking
    for i in range(0, len(packet)/block_size):
        #print packet[i*block_size:i*block_size + block_size]
        if packet[i*block_size:i*block_size + block_size] in freq[i].keys():
            freq[i][packet[i*block_size:i*block_size + block_size]] += 1
        else:
            freq[i][packet[i*block_size:i*block_size + block_size]] = 1

    return freq


#main
fr = open("E:/automobile_fuzzing/can_log/trace_txt/trace.txt", 'r')
id = {}
parameter_n = 6
parameter_m = 2.
block_size = 1  #1:bit 4:half-byte 8:byte
freq = list()
amount = 0
for i in range(0, 64/block_size):  freq.append(dict())

while True:
    line = fr.readline()
    if not line: break
    if line[0] == ";": continue
    #amount += 1
    split_line = line.split()
    data_field = full_data(split_line[5:])

    try:
        id[split_line[3]].append(data_field)
    except KeyError:
        id[split_line[3]] = list()
        id[split_line[3]].append(data_field)
    freq = frequency(data_field, freq, block_size)

for seperate_id in id.keys():
    #sys.stderr.write(str(seperate_id) + "\n")
    transition = Counter(id[seperate_id])
    amount = len(id[seperate_id])
    nodup = list(set(id[seperate_id]))
    #fw2 = open("E:/automobile_fuzzing/can_log/trace_txt/temp/"+seperate_id+".txt", 'w+')
    fw = open("E:/automobile_fuzzing/can_log/trace_txt/temp_cell/"+seperate_id+".txt", 'w+')
    result = learning_labeling(nodup, freq, parameter_m,amount, block_size, fw, parameter_n, transition)

