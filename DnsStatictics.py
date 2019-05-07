import dpkt, time
import sys


def addr2str(addrobj):
    if len(addrobj) != 4:
        return "addr error!"
    else:
        try:
            return str(ord(addrobj[0]))+"."+str(ord(addrobj[1]))+"."+str(ord(addrobj[2]))+"."+str(ord(addrobj[3]))
        except TypeError as e:
            return str(addrobj[0])+"."+str(addrobj[1])+"."+str(addrobj[2])+"."+str(addrobj[3])

    
def get_query_name(dns):
    qnames = []
    for query in dns.qd:
        query_qname = query.name
        qnames.append(query_qname)
    if len(qnames) != 0:
        return qnames[0]
    else:
        answers = dns.an
        for answer in answers:
            answer_name = answer.name
            qnames.append(answer_name)
    if len(qnames) != 0:
        return qnames[0]
    else:
        return None

def get_statistics_info(pcap_file):
    global ele_dict
    statistics_info = []
    data = open(pcap_file, 'rb')
    # data 为二进制数据
    pcap = dpkt.pcap.Reader(data)
    for ts, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue
        # if eth.type != 2048: # IPv4
        #     continue
        try:
            ip = eth.data
        except:
            continue
        # 直到找到IP层
        while not isinstance(ip, dpkt.ip.IP): 
            try:
                ip = ip.data
            except AttributeError:
                # 可能是其他协议，没有data属性
                break
        try:
            sip = addr2str(ip.src)
            dip = addr2str(ip.dst)
            if ip.p != 17: # UDP
                continue
        except AttributeError:
            # 专门处理其他协议数据报文
            continue
        try:
            udp = ip.data
            sport = udp.sport
            dport = udp.dport
        except:
            continue
        if udp.sport != 53 and udp.dport != 53:
            continue
        try:
            dns = dpkt.dns.DNS(udp.data)
        except dpkt.UnpackError as e:
            if e.__str__() == 'Invalid label compression pointer':
                print('This pcap file is a Raw UDP file.')
                break
            else:
                print(e)
                continue
        qname = get_query_name(dns)
        time_stramp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        if len(qname.split('.')) > 2:
                query = '.'.join(qname.split('.')[1:])
        else:
                query = qname
        # response
        if dns.qr == 1:
            # dkey = (sip + ':' + str(sport) + '-' + dip, qname)
            dkey = (sip + ':' + str(sport) + '-' + dip, query)
        else:
            # dkey = (sip  + '-' + dip + ':' + str(dport), qname)
            dkey = (sip  + '-' + dip + ':' + str(dport), query)
        statistics_info.append({dkey : time_stramp})
        
    for s_info in statistics_info:
        skey = list(s_info.keys())[0]
        if skey not in ele_dict:
            ele_dict.update({skey : [s_info[skey]]})
        else:
            ele_dict[skey] = ele_dict[skey] + [s_info[skey]]
    del statistics_info
    for zkey in ele_dict:
        ele_dict[zkey] = sorted(ele_dict[zkey])


if __name__ == '__main__':
    # {(sip:sport - dip:dport, qname):[time_stramp1, time_stramp2, ...]}
    global ele_dict
    ele_dict = {}
    pcap_file = './type-txt.pcap'
    get_statistics_info(pcap_file)
    for ele in ele_dict:
        print(ele)