$vmName = "Aegis-Lab-Android"
$isoPath = "C:\Users\raio\Downloads\android-x86_64-9.0-r2.iso"

# Remove existing if any
Get-VM -Name $vmName -ErrorAction SilentlyContinue | Remove-VM -Force

Write-Output "Creating Gen 2 VM using default Hyper-V path..."
$vm = New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath "C:\ProgramData\Microsoft\Windows\Virtual Hard Disks\android_disk.vhdx" -NewVHDSizeBytes 16GB -SwitchName "Default Switch"

Set-VM -Name $vmName -ProcessorCount 4 -StaticMemory

# Disable Secure Boot (Required for Android-x86 Linux kernel)
Set-VMFirmware -VMName $vmName -EnableSecureBoot Off

# Add DVD Drive with Android ISO
Add-VMDvdDrive -VMName $vmName -Path $isoPath

# Set Boot Order: DVD first
$dvd = Get-VMDvdDrive -VMName $vmName
Set-VMFirmware -VMName $vmName -FirstBootDevice $dvd

Write-Output "Starting Gen 2 Android VM..."
Start-VM -Name $vmName

Start-Process "vmconnect.exe" -ArgumentList "localhost $vmName"
Write-Output "VM Started and vmconnect launched!"
Get-VM -Name $vmName | Select-Object Name, State, MemoryAssigned
