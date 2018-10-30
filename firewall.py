import bisect
import unittest
from intervaltree import IntervalTree


# base rule model
class FireWallRule(object):
    def __init__(self, bound_type, protocal, start_port, end_port, start_ip_range, end_ip_range):
        self.bound_type = bound_type
        self.protocal = protocal
        self.start_port = start_port
        self.end_port = end_port
        self.start_ip = start_ip_range
        self.end_ip = end_ip_range

    def __repr__(self):
        return "direction:%s protocal %s, start_port: %s, end_port: %s, start_ip: %d, end_ip:%d" %(self.bound_type, self.protocal, self.start_port, self.end_port, self.start_ip, self.end_ip)

    def __str__(self):
        return self.__repr__()

class FireWall(object):
    def __init__(self, path):
        self.rules = []
        self.ip_index = []
        self.ip_interval_tree = IntervalTree()
        with open(path) as ins:
            for line in ins:
                rule = self.parse(line.rstrip())
                self.addRule(rule)

        self.ip_index.sort(key=lambda x: (x[0], x[1]))

    def addRule(self, rule):
        self.rules.append(rule)
        self.ip_index.append([rule.start_ip, rule.end_ip, rule])
        self.ip_interval_tree.addi(rule.start_ip, rule.end_ip+1, rule)

    # parse the line into the RULE structure
    def parse(self, line):

        tokens = line.split(',')
        port_s = port_e = port_range = tokens[2]

        ip_s = ip_e = ip_range = tokens[3]
        if '-' in tokens[2]:
            range = port_range.split('-')
            port_s = range[0]
            port_e = range[1]

        if '-' in tokens[3]:
            range = ip_range.split('-')
            ip_s = self.ip_fill_zero(range[0])
            ip_e = self.ip_fill_zero(range[1])
        else:
            ip_s = ip_e = self.ip_fill_zero(tokens[3])

        return FireWallRule(tokens[0], tokens[1], int(port_s), int(port_e), ip_s, ip_e)

    # fill zero if each segment of ip address length is less than 3
    def ip_fill_zero(self, ip):
        ip_arr = ip.split('.')
        ans = ''
        for i in ip_arr:
            ans+=(i.zfill(3))

        return int(ans)

    def accept_packet(self, dir, protocal, port, ip):
        ip = self.ip_fill_zero(ip)
        port = int(port)
        intervals = self.ip_interval_tree[ip]
        if intervals == None:
            return False
        else:
            for interval in intervals:
                rule = interval[2]
                if protocal == rule.protocal \
                        and rule.bound_type == dir \
                        and port >= rule.start_port \
                        and port <= rule.end_port:
                    return True
            return False

        '''
        ip_arr = [ips[0] for ips in self.ip_index]
        #binary search index, ip look up list could be more optimized by using B+ Tree
        index = bisect.bisect(ip_arr, ip)
        if index >= len(self.ip_index):
            index = len(self.ip_index) - 1
        for i in range(index, -1, -1):
            rule = self.ip_index[i][2]
            # could be write as rule chains Rule.apply(ip_policy).apply(port_polocy)
            if self.ip_index[i][1] >= ip and \
                    protocal == rule.protocal and \
                    rule.bound_type == dir and \
                    port >= rule.start_port and \
                    port <= rule.end_port:
                return True
        return False
        '''


class TestFireWall(unittest.TestCase):
    def setUp(self):
        self.fw = FireWall('rules.txt');
        self.anyRule = FireWallRule('inbound', 'tcp', 0, 65535, 0, 255255255255)



    def test_validate_1(self):
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '80', '192.168.1.2'))
        self.assertFalse(self.fw.accept_packet('outbound', 'udp', '80', '192.168.1.2'))
        self.assertFalse(self.fw.accept_packet('outbound', 'tcp', '0', '192.168.1.2'))

    # inbound,udp,53,192.168.1.1-192.168.2.5
    def test_validate_ip_range(self):
        self.assertTrue(self.fw.accept_packet('inbound', 'udp', '53', '192.168.1.1'))
        self.assertTrue(self.fw.accept_packet('inbound', 'udp', '53', '192.168.2.5'))
        self.assertTrue(self.fw.accept_packet('inbound', 'udp', '53', '192.168.1.110'))
        self.assertFalse(self.fw.accept_packet('inbound', 'udp', '53', '192.168.2.6'))

    def test_validate_port_range(self):
        self.assertTrue(self.fw.accept_packet('outbound', 'udp', '1000', '52.12.48.92'))
        self.assertTrue(self.fw.accept_packet('outbound', 'udp', '2000', '52.12.48.92'))
        self.assertFalse(self.fw.accept_packet('outbound', 'udp', '2001', '52.12.48.92'))

    #inbound,tcp,5,0.0.0.0-255.255.255.255
    def test_validate_any_rule(self):
        self.fw.addRule(self.anyRule)
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '5', '52.12.48.92'))
        self.assertFalse(self.fw.accept_packet('inbound', 'tcp', '65536', '255.255.255.255'))
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '65535', '255.255.255.255'))
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '5', '0.0.0.0'))

    def test_validate_rule_overlapping(self):
        self.fw = FireWall('rules.txt');
        rule1 = FireWallRule('inbound', 'tcp', 1, 100, 0, 192168001001)
        rule2 = FireWallRule('inbound', 'tcp', 1, 101, 192168001001, 192168002255)
        self.fw.addRule(rule1)
        self.fw.addRule(rule2)
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '1', '0.0.0.0'))
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '2', '192.168.1.1'))
        self.assertFalse(self.fw.accept_packet('inbound', 'tcp', '102', '192.168.1.1'))
        self.assertTrue(self.fw.accept_packet('inbound', 'tcp', '101', '192.168.2.255'))
        self.assertFalse(self.fw.accept_packet('inbound', 'tcp', '102', '192.168.2.255'))


if __name__ == '__main__':
    unittest.main()
