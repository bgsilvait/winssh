# 



### <span style="font-family: times, serif; font-size:16pt; font-style:italic;"> winssh

<span style="font-family: calibri, Garamond, 'Comic Sans MS' ;">Enable SSH to Access Windows Server.</span>


* Run this project as the Administrator user:
```
Invoke-WebRequest -OutFile Enablessh_user_and_key.ps1 https://raw.githubusercontent.com/bgsilvait/winssh/master/Enablessh_user_and_key.ps1
.\Enablessh_user_and_key.ps1
```
```
# Enablessh_user_and_key.ps1
USAGE: Enablessh_user_and_key [ -RunMode =default|key|full ]

OPTIONS:
   -RunMode  Has three parameters  1) default, 2) key 3) full:
             default       Install sshd for access the Windows using user and password.
             key           key   Install sshd, creates a new user "ec2-user", disable password authentication.
             full          Runs the Key mode + chocolatey

Enable user + key withou password: 
Enablessh_user_and_key.ps1 -RunMode key 
```
* For Userdata:
```
<powershell>
Invoke-WebRequest -OutFile Enablessh_user_and_key.ps1 https://raw.githubusercontent.com/bgsilvait/winssh/master/Enablessh_user_and_key.ps1
.\Enablessh_user_and_key.ps1 -RunMode full
&$PSHOME\profile.ps1
choco install vim curl awscli -y
</powershell>
```
