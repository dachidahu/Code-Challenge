
import bisect
import unittest

#base rule model
class FireWallRule(object):
    def __init__(self, bound_type, protocal, start_port, end_port, start_ip_range, end_ip_range):
        self.bound_type = bound_type
        self.protocal = protocal
        self.start_port = start_port
        self.end_port = end_port
        self.start_ip = start_ip_range
        self.end_ip = end_ip_range


class FireWall(object):
    def __init__(self, path):
        self.rules = []
        self.ip_index = []
        with open(path) as ins:
            for line in ins:
                rule = self.parse(line.rstrip())
                self.addRule(rule)

        self.ip_index.sort(key = lambda x: (x[0], x[1]))

    def addRule(self, rule):
        self.rules.append(rule)
        self.ip_index.append([rule.start_ip, rule.end_ip, rule])

    #parse the line into the RULE structure
    def parse(self, line):
        ans = line.split(',')
        port_s = port_e = port_range = ans[2]

        ip_s = ip_e = ip_range = ans[3]
        if '-' in ans[2]:
            range = port_range.split('-')
            port_s = range[0]
            port_e = range[1]

        if '-' in ans[3]:
            range = ip_range.split('-')
            ip_s = self.ip_fill_zero(range[0])
            ip_e = self.ip_fill_zero(range[1])
        else:
            ip_s = ip_e = self.ip_fill_zero(ans[3])

        return FireWallRule(ans[0], ans[1], port_s, port_e, ip_s, ip_e)

    #fill zero if each segment of ip address length is less than 3
    def ip_fill_zero(self, ip):
        ip_arr = ip.split('.')
        ans = []
        for i in ip_arr:
            ans.append(i.zfill(3))
        return '.'.join(ans)


    def validate(self, dir, protocal, port, ip):
        ip = self.ip_fill_zero(ip)
        ip_arr = [ips[0] for ips in self.ip_index]
        #binary search index, ip look up list could be more optimized by using B+ Tree
        index = bisect.bisect(ip_arr, ip)

        if index >= len(self.ip_index):
            index = len(self.ip_index)-1
        for i in range(index, -1, -1):
            rule = self.ip_index[i][2]
            #could be write as rule chains Rule.apply(ip_policy).apply(port_polocy)
            if self.ip_index[i][1] >= ip and \
                    protocal == rule.protocal and \
                    rule.bound_type == dir and \
                    port >= rule.start_port and \
                    port <= rule.end_port:
                return True
        return False


class TestFireWall(unittest.TestCase):
    def setUp(self):
        self.fw = FireWall('rules.txt');

    def test_validate_1(self):
        self.assertTrue(self.fw.validate('inbound', 'tcp', '80', '192.168.1.2'))
        self.assertFalse(self.fw.validate('outbound', 'udp', '80', '192.168.1.2'))
        self.assertFalse(self.fw.validate('outbound', 'tcp', '0', '192.168.1.2'))

    # inbound,udp,53,192.168.1.1-192.168.2.5
    def test_validate_ip_range(self):
        self.assertTrue(self.fw.validate('inbound', 'udp', '53', '192.168.1.1'))
        self.assertTrue(self.fw.validate('inbound', 'udp', '53', '192.168.2.5'))
        self.assertTrue(self.fw.validate('inbound', 'udp', '53', '192.168.1.110'))
        self.assertFalse(self.fw.validate('inbound', 'udp', '53', '192.168.2.6'))

    def test_validate_port_range(self):
        self.assertTrue(self.fw.validate('outbound', 'udp', '1000', '52.12.48.92'))
        self.assertTrue(self.fw.validate('outbound', 'udp', '2000', '52.12.48.92'))
        self.assertFalse(self.fw.validate('outbound', 'udp', '2001', '52.12.48.92'))

if __name__ == '__main__':
    unittest.main()