# Code-Challenge

Due to need to query the overlapping ip address, I use the third-party library called intervaltree. So it needs to install intervaltree 
 before running it. 
 
 Installing
----------

```sh
pip install intervaltree
```

Features
----------
* Initializing
    *  `fw = FireWall('path of your rule file')`
* addRule
Adding a rule to firewall (Time Complexity O(logn))
    *   fw.addRule('direction', 'protocal' start_port, end_port, start_ip, end_ip)
    *   direiction(string):"inbound" or "outbound"
    *   protocal(string):exactly one of “tcp” or “udp”, all lowercase
    *   start_port: an integer from 0 to 65535
    *   end_port: an integer from 0 to 65535
    *   start_ip: an integer from 0 to 255255255255
    *   end_ip: an integer from 0 to 255255255255
* accept_packet (Time Complexity O(logn + m  where n is total rules in interval tree and m is number of match items)
    * fw.accept_packet('direction', 'protocal', 'port', 'ip_address')
    * it takes exactly four arguments and returns a boolean:
    true, if there exists a rule in the file that this object was initialized with that allows traffic
    with these particular properties, and false otherwise.
    * direction (string): “inbound” or “outbound”
    * protocol (string): exactly one of “tcp” or “udp”, all lowercase
    * port (string) –  range [1, 65535]
    * ip_address (string): a single well-formed IPv4 address
 
 Example
----------
  ``` python
  >>> fw = FireWall('rules.txt'); 
  >>> fw.addRule('inbound', 'tcp', 0,65535, 0, 255255255255) #allows any tcp connection incoming
  >>> fw = accept_packet('inbound', 'tcp', '80', '192.168.1.1')
  True
  ```
 
 Interested Team
----------
 * I am interested in platform  team which is perfectly match what I have experienced.
