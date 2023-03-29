import pyshark
import matplotlib.pyplot as plt

scenario1 = pyshark.FileCapture("./classique/sc1-4msg.pcapng")
scenario2 = pyshark.FileCapture("./classique/sc2-10sec-sc.pcapng")
scenario3 = pyshark.FileCapture("./classique/sc3-10sec-ac.pcapng")
scenario4 = pyshark.FileCapture("./classique/sc4-10sec-sc-p.pcapng")
scenario5 = pyshark.FileCapture("./classique/sc5-10sec-av-p.pcapng")

def division(trace):
    trace.load_packets()
    time = {}
    for pkt in range(len(trace)):
        d = trace[pkt].sniff_time
        minute = d.minute
        seconde = d.second
        if seconde <=15 :
            if str(minute)+"+1" not in time:
                time[str(minute)+"+1"] = [pkt]
            else :
                time[str(minute)+"+1"].append(pkt)
        elif seconde <=30 :
            if str(minute)+"+2" not in time:
                time[str(minute)+"+2"] = [pkt]
            else :
                time[str(minute)+"+2"].append(pkt)
        elif seconde <=45 :
            if str(minute)+"+3" not in time:
                time[str(minute)+"+3"] = [pkt]
            else :
                time[str(minute)+"+3"].append(pkt)
        else :
            if str(minute)+"+4" not in time:
                time[str(minute)+"+4"] = [pkt]
            else :
                time[str(minute)+"+4"].append(pkt)
    newtrace = []
    for i in range(len(time)):
        newtrace.append([])
    index = 0
    for key in time.keys():
        for j in time[key]:
            newtrace[index].append(trace[j])
        index+=1
    return newtrace

def Ratio(Newtrace):
    lst = []
    count = []
    for i in range(len(Newtrace)):
        lst.append([])
        count.append([])
    index = 0
    for j in Newtrace:
        for pkt in j:
            if pkt.highest_layer not in lst[index]:
                lst[index].append(pkt.highest_layer)
        taillelst = len(lst[index])
        for i in range(taillelst):
            count[index].append(0)
        for pkt in j:
            for k in range(taillelst):
                if pkt.highest_layer == lst[index][k]:
                    count[index][k] += 1
        index+=1
    return lst, count




nt = division(scenario1)
label, data= Ratio(nt)
for i in label:
    print(i)
for i in data:
    print(i)