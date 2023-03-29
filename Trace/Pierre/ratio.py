import pyshark
import matplotlib.pyplot as plt

scenario1 = pyshark.FileCapture("./classique/sc1-4msg.pcapng")
scenario2 = pyshark.FileCapture("./classique/sc2-10sec-sc.pcapng")
scenario3 = pyshark.FileCapture("./classique/sc3-10sec-ac.pcapng")
scenario4 = pyshark.FileCapture("./classique/sc4-10sec-sc-p.pcapng")
scenario5 = pyshark.FileCapture("./classique/sc5-10sec-av-p.pcapng")

def getRatio(trace):
    trace.load_packets()
    lst = []
    for pkt in trace:
        if pkt.highest_layer not in lst:
            lst.append(pkt.highest_layer)
    taillelst = len(lst)
    count = []
    for i in range(taillelst):
        count.append(0)
    for pkt in trace:
        for j in range(taillelst):
            if pkt.highest_layer == lst[j]:
                count[j] += 1
    return lst, count

def pourcentage(value, somme):
    return (value/somme)*100

def pichart(data, labels):
    som = 0
    for i in data:
        som += i
    for j in range(len(data)):
        data[j] = pourcentage(data[j], som)
        data[j] = round(data[j], 2)
    for k in range(len(labels)):
        if labels[k] == "_WS.MALFORMED":
            labels[k] = "WS.MALFORMED"
        elif labels[k] == "DATA":
            labels[k] = "UDP"
        labels[k] = labels[k]+" ("+str(data[k])+" %)"
    plt.pie(data)
    plt.legend(labels, loc="best")
    plt.axis('equal')
    plt.title("percentage of package in a scenario")
    plt.tight_layout()
    plt.show()


label1, data1 = getRatio(scenario1)
label2, data2 = getRatio(scenario2)
label3, data3 = getRatio(scenario3)
label4, data4 = getRatio(scenario4)
label5, data5 = getRatio(scenario5)

pichart(data1, label1)
pichart(data2, label2)
pichart(data3, label3)
pichart(data4, label4)
pichart(data5, label5)