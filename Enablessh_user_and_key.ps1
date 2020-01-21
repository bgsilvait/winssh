# Common functions
# ---------------------------------------------------------------------------------------

Function is_elevated{
    If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-warning "This script requires elevated privileges to change files and Install Windows Features."
        Write-Host "Please re-launch as Administrator." -foreground "red" -background "black"
        break
    }
}
Function install_ssh{
    try {
        Write-Host "Installing SSHd and Set Powershell as default Session"
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        Set-Service sshd -StartupType Automatic
        Set-Service ssh-agent -StartupType Automatic
        Start-Service sshd
        Start-Service ssh-agent
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        Write-Host "OK" -foregroundcolor "green"
    }
    catch {
        Write-Error "Fail to Install SSHd"
        break
    }
}
