$vmName = "Aegis-Lab-Android"
$isoPath = "C:\Users\raio\Downloads\android-x86_64-9.0-r2.iso"
$vmDir = "C:\Users\raio\Hyper-V\Aegis-Lab-Android"
$vhdPath = "$vmDir\Virtual Hard Disks\disk.vhdx"

New-Item -ItemType Directory -Path "$vmDir\Virtual Hard Disks" -Force | Out-Null

# Remove existing if any
Get-VM -Name $vmName -ErrorAction SilentlyContinue | Remove-VM -Force

Write-Output "Creating VHDX (16GB)..."
New-VHD -Path $vhdPath -SizeBytes 16GB -Dynamic | Out-Null

Write-Output "Creating VM $vmName..."
$vm = New-VM -Name $vmName -Generation 1 -MemoryStartupBytes 4GB -VHDPath $vhdPath -SwitchName "Default Switch" -Path $vmDir

Set-VM -Name $vmName -ProcessorCount 4 -StaticMemory

Write-Output "Attaching Android ISO to IDE controller..."
Set-VMDvdDrive -VMName $vmName -ControllerNumber 1 -ControllerLocation 0 -Path $isoPath

# Set Boot Order: CD first, then IDE
Set-VMBios -VMName $vmName -StartupOrder @("CD", "IDE", "LegacyNetworkAdapter", "Floppy")

Write-Output "VM Configuration Complete!"
Get-VM -Name $vmName | Select-Object Name, State, MemoryAssigned, ProcessorCount
