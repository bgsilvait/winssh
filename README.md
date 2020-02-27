# Enable SSH Access on Windows Server.

## Introduction

**winssh** is a Powershell script that installs and configures sshd service on Windows Server(2019 and later versions are supported). You can choose 3 different **RunModes**:

- default

Install sshd for access Windows Server using user and password for authentication.

- key

Install sshd, creates a new local user "ec2-user" without password, adds "ec2-user" as Local Administrator, disable password authentication for ssh and adds the AWS Key pair used in the creation of EC2 as trust key for ssh.

- full

key mode + [powerash](https://github.com/bgsilvait/powerash)


## Usage

### In a powershell session:

**Run this project as the Administrator user**
```
iwr -o winssh.ps1 https://raw.githubusercontent.com/bgsilvait/winssh/master/winssh.ps1
.\winssh.ps1 -RunMode full
```

### For AWS EC2 Userdata:
```
<powershell>
iwr -o winssh.ps1 https://raw.githubusercontent.com/bgsilvait/winssh/master/winssh.ps1
.\winssh.ps1 -RunMode full
&$PSHOME\profile.ps1
choco install vim curl awscli -y
&$PSHOME\profile.ps1
</powershell>
```

## Access the Windows Server key/full RunMode

```
ssh -i key.pem ec2-user@ip
```

## Access the Windows Server default RunMode

```
ssh administrator@ip
```


```console
eksctl create cluster --name=eks-windows --ssh-access \
--ssh-public-key=your_key_name --managed --region=us-east-1
```
