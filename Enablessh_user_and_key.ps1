param(
    [Parameter(Mandatory=$False)][string]$RunMode = "default"   
    )


# Common functions
# ---------------------------------------------------------------------------------------#

Function is_elevated{
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-warning "This script requires elevated privileges to change Install Windows Features and change files."
        Write-Host "Please re-launch the Powershell Session as Administrator." -foreground "red" -background "black"
        break
    }
}
Function install_ssh{
    try {
        Write-Host "Installing SSHd and Set Powershell as default Session" -foregroundcolor "yellow"
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Set-Service sshd -StartupType Automatic
        Set-Service ssh-agent -StartupType Automatic
        Start-Service sshd
        Start-Service ssh-agent
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        Get-Service *ssh*
        Write-Host "OK" -foregroundcolor "green"
    }
    catch {
        Write-Error "Fail to Install SSHd"
        break
    }
}

# Security Settings
# ---------------------------------------------------------------------------------------#

Function add_key{
    try {
        $key = "$(Invoke-RestMethod -uri  http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key)"
        add-Content -Path 'C:\ProgramData\ssh\administrators_authorized_keys' -Value $key
        $acl = Get-Acl C:\ProgramData\ssh\administrators_authorized_keys
        $acl.SetAccessRuleProtection($true, $false)
        $administratorsRule = New-Object system.security.accesscontrol.filesystemaccessrule("Administrators","FullControl","Allow")
        $systemRule = New-Object system.security.accesscontrol.filesystemaccessrule("SYSTEM","FullControl","Allow")
        $acl.SetAccessRule($administratorsRule)
        $acl.SetAccessRule($systemRule)
        $acl | Set-Acl
        }
        catch {
            Write-Error "Fail to set ssh key"
            break
        }
    }

    Function add_useradm{
        try {
            New-LocalUser -Name "ec2-user" -Description "ec2-user without password." -NoPassword
            Add-LocalGroupMember -Group "Administrators" -Member "ec2-user"
        }
        catch {
            Write-Error "Fail to Create ec2-user without password"
            break
        }
    }

    Function disable_password_auth{
        try {
            Stop-service sshd
            $Filepath = "C:\ProgramData\ssh\sshd_config"
            $File = (Get-Content "C:\ProgramData\ssh\sshd_config")
            IF($File -match "#PasswordAuthentication yes"){
            $File -Replace "#PasswordAuthentication yes","PasswordAuthentication no" | Set-Content $Filepath}
            Start-Service sshd
        }
        catch {
            Write-Error "Fail to modify sshd_config file"
            break
        }
    }

    Function choco{
        try {
            Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            refreshenv
            choco install awscli vim curl -dvfy
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
        }
        catch {
            Write-Error "fail to install chocolatey"
            break
        }
    }

    Function extras{
        try {
            if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
           # Your script here
            choco install awscli vim curl -dvfy 
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
        }
        catch {
            Write-Error "fail to install chocolatey packages"
            break
        }
    }


Function install{
    is_elevated
    install_ssh
}

Function key_withoutpass{
    install
    add_key
    add_useradm
    disable_password_auth
   
}

Function full{
    install
    key_withoutpass
    choco
    
}

Function full2{
    choco
    
}

if ($RunMode -eq "default"){
    Write-Host "Running Default Mode" -foregroundcolor "green"
    install
} elseif ($RunMode -eq "key"){
    Write-Host "Running Key Mode" -foregroundcolor "blue"
    key_withoutpass
} elseif ($RunMode -eq "full"){
    Write-Host "RUnning Full Mode" -foregroundcolor "blue"
    full
} elseif ($RunMode -eq "full2"){
    Write-Host "RUnning Full2 Mode" -foregroundcolor "blue"
    full2
} else {
    Write-Host "You need to specify either default, key or full RunMode" -ForegroundColor "red" 
    Break
}
