## Zeekbro Exercise
Investigate a series of traffic data and stop malicious activity under different scenarios. 
Let's start working with Zeek to analyse the captured traffic.

### Anomalous DNS
*An alert triggered: "Anomalous DNS Activity".* <br>
The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 

1. Investigate the dns-tunneling.pcap file. Investigate the dns.log file. What is the number of DNS records linked to the IPv6 address? <br>
  - Analyze the packet file: ``zeek -Cr dns-tunneling.pcap``<br>
  - Examine the ``dns.log`` using ``cat dns.log | less``. the AAAA (often read as "quad-A") is a dns record type indicating IPv6 address, while IPv4 uses A records.<br>
  - Search the number of IPv6 address: ``cat dns.log | zeek-cut qtype_name | grep "AAAA" | uniq -c``
3. Investigate the ``conn.log`` file. What is the longest connection duration?<br>
  `` cat conn.log | zeek-cut duration | sort -n``
4. Investigate the ``dns.log`` file. Filter all unique DNS queries. What is the number of unique domain queries?<br>
  ``cat dns.log | zeek-cut query | rev | cut -d '.' -f 1-2 | sort | uniq | rev``
5. There are a massive amount of DNS queries sent to the same domain. This is abnormal. Let's find out which hosts are involved in this activity.
   Investigate the ``conn.log`` file. What is the IP address of the source host? <br>
  ``cat conn.log |zeek-cut id.orig_h id.resp_h | sort -n | uniq -c``

### Phishing
*An alert triggered: "Phishing Attempt".* <br>
The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive. 

1. Investigate the logs. What is the suspicious source address? Enter your answer in defanged format.
  - Read the ``phishing.pcap`` file using ``zeek -Cr phishing.pcap``
  - Open ``dhcp.log`` file: ``cat dhcp.log``
  - Search for source client_addr: ``cat dhcp.log | zeek-cut client_addr | uniq`` add `` | sed -e 's/\./[.]/g'`` for defanged format or use *cyberchef*. 
3. Investigate the ``http.log`` file. Which domain address were the malicious files downloaded from? Enter your answer in defanged format.
  - ``cat http.log``
  - Try to search using host and uri value: ``cat http.log | zeek-cut host uri``.
  - find the malicious domain and change into defanged format using *cyberchef*.
4. Investigate the malicious document in VirusTotal. What kind of file is associated with the malicious document?
  - `` zeek -Cr phishing.pcap hash-demo.zeek ``
  - `` cat files.log``
  - ``cat files.log | zeek-cut mime_type md5 | grep "word"``
  - Search by md5 value on *virustotal*, go to the relations tab and find the filetype.
5. Investigate the extracted malicious ``.exe`` file. What is the given file name in Virustotal?<br>
  - cat files.log | zeek-cut mime_type md5 | grep "exe"
  -  Search by md5 value on *virustotal*.
6. Investigate the ``malicious .exe`` file in VirusTotal. What is the contacted domain name? Enter your answer in defanged format.
  - Go to behavior tab > dns resolution, find the domain name and change into defanged format. 
7. Investigate the ``http.log`` file. What is the request name of the downloaded ``malicious .exe`` file?<br>
``cat http.log | zeek-cut host uri``

### Log4J
*An alert triggered: "Log4J Exploitation Attempt".* <br>
The case was assigned to you. Inspect the PCAP and retrieve the artefacts to confirm this alert is a true positive.

1. Investigate the ``log4shell.pcapng`` file with ``detection-log4j.zeek`` script. Investigate the ``signature.log`` file. What is the number of signature hits?
- check the script: `` nano detection-log4j.zeek``
- breakdown the pcap file: ``zeek -Cr log4shell.pcapng detection-log4j.zeek``
- ``cat signatures.log | zeek-cut sig_id | wc -l`` we used sig_id to determine the number of signature hits

2. Investigate the ``http.log`` file. Which tool is used for scanning?
- `` cat http.log`` nmap is the common tool used for scanning
- or we can use `` cat http.log | zeek-cut user_agent | sort | uniq -c

4. Investigate the ``http.log`` file. What is the extension of the exploit file?
- `` cat http.log | zeek-cut uri | sort | uniq -c``

6. Investigate the log4j.log file. Decode the base64 commands. What is the name of the created file?
- ``cat log4j.log | head -20 `` examine the value contains encoded base64 command, try to decoded it using cyberchef.
- Pay attention to the commands used for file creation, such as ``nano``, ``touch``, ``vim``, etc.

### Reference
- Challenge Lab: https://tryhackme.com/room/zeekbroexercises
















