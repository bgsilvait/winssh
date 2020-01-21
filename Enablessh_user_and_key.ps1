param(
    [Parameter(Mandatory=$False)][string]$RunMode = "Test1"   
    )


# Common functions
# ---------------------------------------------------------------------------------------

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

Function install{
    is_elevated
    install_ssh
    

}

if ($RunMode -eq "Test1"){
    Write-Host "Running Default(Test1) Mode" -foregroundcolor "green"
    install

} else {
    Write-Host "You need to specify either Test1, EnableDebug or DisableDebug RunMode" -ForegroundColor "red" 
    Break
}
