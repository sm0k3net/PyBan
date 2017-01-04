# PyBan
Python script to analyze log for sql injection &amp; xss, create formated log or ban IPs


Script is very simple for usage, but to be able to ban IPs after log was analyzed - need to have root privileges.

Available commands:
 * ban - reads log and if some type of attacks like SQL Injection or XSS detected 3 or more times from 1 IP address, it will be banned via iptables
 * log - creates easy to read log file with detected SQL Injection or XSS attacks called "pyban.log"
 
 HOW TO USE:
 <pre>
 $ chmod +x pyban.py
 $ ./pyban.py /var/log/apache2/ access log
 $ ./pyban.py /var/log/apache2/ access ban
 </pre>
 
 In first parameter you need to set path to your logs, in second parameter - choose which logs you want to read: access or error logs. And in third parameter you choose action what to do - create formated log file or just ban IP addresses.
 
 Want to warn that regular expressions are not universal for 100% of cases, so first of all better to create log file and see what possibly will be banned.
