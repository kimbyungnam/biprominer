from collections import Counter
from time import sleep


#get rid of duplication
def unduplication(packet):
    nodup = list(set(packet))

    return nodup

#combination of learning phase and labeling phase
def learning_labeling(packet, freq, parameter, amount, block_size, fw):
    cell_list = []
    fw3 = open("E:/automobile_fuzzing/can_log/trace_txt/test.txt", 'w+')#file writings are just for testing
    while True:# loop until there is no more cell
        cell_len = len(cell_list)
        fw3.write(str(len(packet))+"\n")
        #print str(len(packet)),

        for j in range(0,len(packet)):
            check = Counter(packet[j])
            labeled = check[' ']/block_size
            unlabeled = len(packet[j])/block_size - labeled# parameter h

            if unlabeled == 0: continue

            threshold = amount/(parameter * unlabeled)
            fw3.write(str(len(packet[j])) + "\t"+ str(len(packet[j])/block_size)+"\n")

            for i in range(0, len(packet[j]) / block_size):
                if packet[j][i*block_size] == " ": continue
                block = packet[j][i*block_size:i*block_size+block_size]
                if freq[i][block] >= threshold:
                    cell = {}
                    cell['START'] = i*block_size#start index
                    cell['END'] = i*block_size + block_size -1#end index
                    cell['value'] = block#cell value
                    cell_list.append(cell)
                    packet[j] = packet[j][0:i*block_size]+" " * block_size + packet[j][i*block_size + block_size:]

                    fw.write("START: "+str(cell['START'])+"\tEND: "+str(cell['END'])+"\tvalue: "+str(cell['value'])+"\n")

        if cell_len == len(cell_list):# check there is new cell creation
            print "all done"
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
parameter_m = 5
block_size = 8  #1:bit 4:half-byte 8:byte
freq = list()
amount = 0;
for i in range(0, block_size):  freq.append(dict())

while True:
    line = fr.readline()
    if not line: break
    if line[0] == ";": continue
    amount += 1
    split_line = line.split()
    data_field = full_data(split_line[5:])

    try:
        id[split_line[3]].append(data_field)
    except KeyError:
        id[split_line[3]] = list()
        id[split_line[3]].append(data_field)
    freq = frequency(data_field, freq, block_size)

for seperate_id in id.keys():
    nodup = list(set(id[seperate_id]))
    fw2 = open("E:/automobile_fuzzing/can_log/trace_txt/temp/"+seperate_id+".txt", 'w+')
    fw = open("E:/automobile_fuzzing/can_log/trace_txt/temp_cell/"+seperate_id+".txt", 'w+')
    result = learning_labeling(nodup, freq, parameter_m,amount, block_size, fw)

