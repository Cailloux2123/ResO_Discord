import pyshark as ps

#tentation de test avec le package pyshark

scenario1 = ps.FileCapture('./sc1-4msg.pcapng')


def getDNS_info(pkt, idx):
    try:
        if pkt.highest_layer == "DNS" and pkt.dns.qry_name:
            print("Numéro du paquet :", idx, "Adresse source de la demande :", pkt.ip.src, "Domaine contacté :", pkt.dns.qry_name)
    except AttributeError as e:
        pass

def Display_info_dns(trace):
    trace.load_packets()
    count = 1
    for pkt in trace:
        getDNS_info(pkt, count)
        count +=1

Display_info_dns(scenario1)