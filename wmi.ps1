function Get-RegistryValueData{
    [CmdletBinding(SupportsShouldProcess=$True,
        ConfirmImpact='Medium',
        HelpURI='http://vcloud-lab.com')]
    Param
    ( 
        [parameter(Position=0, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [alias('C')]
        [String[]]$ComputerName = '.',
        [Parameter(Position=1, Mandatory=$True, ValueFromPipelineByPropertyName=$True)] 
        [alias('Hive')]
        [ValidateSet('ClassesRoot', 'CurrentUser', 'LocalMachine', 'Users', 'CurrentConfig')]
        [String]$RegistryHive = 'LocalMachine',
        [Parameter(Position=2, Mandatory=$True, ValueFromPipelineByPropertyName=$True)]
        [alias('KeyPath')]
        [String]$RegistryKeyPath = 'SYSTEM\CurrentControlSet\Services\USBSTOR',
        [parameter(Position=3, Mandatory=$True, ValueFromPipelineByPropertyName=$true)]
        [alias('Value')]
        [String]$ValueName = 'Start'
    )
    Begin {
        $RegistryRoot= "[{0}]::{1}" -f 'Microsoft.Win32.RegistryHive', $RegistryHive
        try {
            $RegistryHive = Invoke-Expression $RegistryRoot -ErrorAction Stop
        }
        catch {
            Write-Host "Incorrect Registry Hive mentioned, $RegistryHive does not exist" 
        }
    }
    Process {
        Foreach ($Computer in $ComputerName) {
            if (Test-Connection $computer -Count 2 -Quiet) {
                $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computer)
                $key = $reg.OpenSubKey($RegistryKeyPath)
                $Data = $key.GetValue($ValueName)
                $Obj = New-Object psobject
                $Obj | Add-Member -Name Computer -MemberType NoteProperty -Value $Computer
                $Obj | Add-Member -Name RegistryValueName -MemberType NoteProperty -Value "$RegistryKeyPath\$ValueName"
                $Obj | Add-Member -Name RegistryValueData -MemberType NoteProperty -Value $Data
                $Obj
            }
            else {
                Write-Host "$Computer not reachable" -BackgroundColor DarkRed
            }
        }
    }
    End {
        #[Microsoft.Win32.RegistryHive]::ClassesRoot
        #[Microsoft.Win32.RegistryHive]::CurrentUser
        #[Microsoft.Win32.RegistryHive]::LocalMachine
        #[Microsoft.Win32.RegistryHive]::Users
        #[Microsoft.Win32.RegistryHive]::CurrentConfig
    }
}  #תשאול ריגסטרי
function Get-Localadmins{
  [cmdletbinding()]
  Param(
          # List of hostnames - if omited getting information about local machine
        [Parameter(Mandatory=$False,
                   Position=0)]
        [String[]]$ComputerName = [System.Environment]::MachineName,
        
        # Credentials - if not specified using curently logged user
        [Parameter(Mandatory=$False,
                   Position=1)]
        [System.Management.Automation.PSCredential]
        $Credentials = [System.Management.Automation.PSCredential]::Empty
  )


Try 

    {

        $Group = Get-wmiobject Win32_Group -ComputerName $ComputerName -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
        $Query = "GroupComponent = `"Win32_Group.Domain='$($Group.Domain)'`,Name='$($Group.name)'`""
        $List = Get-WmiObject Win32_Groupuser -ComputerName $ComputerName -Filter $query
        $List | %{$_.PartComponent} | % {$_.Substring($_.Lastindexof("Domain=") + 7).Replace("`",Name=`"","\")}

    }

Catch

    {
 
        ([ADSI]"WinNT://$ComputerName/Administrators,group").psbase.Invoke('Members') | foreach { $_.GetType().InvokeMember('ADspath', 'GetProperty', $null, $_, $null).Replace('WinNT://', '') }

    }

                        } # תשאול לוקאל אדמין
Function Get-Uptime{
Param ( [string] $ComputerName = $env:COMPUTERNAME )
$os = Get-WmiObject win32_operatingsystem -ComputerName $ComputerName -ErrorAction SilentlyContinue
 if ($os.LastBootUpTime) {
   $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
   $last = ("Last boot: " + $os.ConvertToDateTime($os.LastBootUpTime) )
   Write-Output ("" + $uptime.Days + " Days " + $uptime.Hours + " Hours " + $uptime.Minutes + " Minutes" )
  }
  else {
    Write-Warning "Unable to connect to $computername"
  }
} # זמן פעולת מכונה
Function Get-Laptop{
 Param(
[string] $ComputerName = $env:COMPUTERNAME 
 )
 if(Get-WmiObject -Class win32_systemenclosure -ComputerName $ComputerName |
    Where-Object { $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 `
    -or $_.chassistypes -eq 14})
   {“its a laptop”}
else{“its a Desktop”}
} # תשאול האם משחב שולחני או נייד
function testPorts{
param(
[string]$ComputerName = $env:COMPUTERNAME
)
#fill this list
$PortsList=@(
"445"
)
for ($i=0 ; $i -lt $PortsList.Count ; $i++) {
$test=test-NetConnection -ComputerName $ComputerName -Port $PortsList[$i] 
if($test.TcpTestSucceeded -ccontains "True"){
$test.RemotePort
}
else{}
}
} # בדיקת מצב פורטים גירסת פוורשל 5.1 ומעלה !
#spessific computers
$Computers = "localhost"
#spessific computers ou
#$Computers = Get-ADComputer -Filter * -SearchBase "OU=LeonardoClubDeadSea,OU=Computers,OU=Fattal-Hotels,DC=fattal,DC=co,DC=il" | select Name
#$Computers = $Computers.name

 foreach ($ComputerName in $Computers){

 Write-Host "Check $ComputerName"
 
 if (Test-Connection $ComputerName -Count 2 -Quiet)

   {
   Write-Host "Reacheble $ComputerName " -BackgroundColor Green

 # Check SMB1 Status - לא עובד טוב
 $SMB =  Get-RegistryValueData -RegistryHive LocalMachine -RegistryKeyPath SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -ValueName SMB1 -ComputerName $ComputerName -ErrorAction SilentlyContinue

    if ($SMB.RegistryValueData -like "1") {$SMB = "Enabled"}
    if ($SMB.RegistryValueData -like "0" ) {$SMB = "Disabled"}
    if ($SMB.RegistryValueData -like $null ){$SMB = "Enable"}




 # Check Domain FW Status - לא עובד טוב
    
        $FW =  (Get-RegistryValueData -RegistryHive LocalMachine -RegistryKeyPath System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile -ValueName EnableFirewall -ComputerName $ComputerName -ErrorAction SilentlyContinue).RegistryValueData
   try {
        if ($FW -like "1" ) {$FW = "Enabled" }
        elseif ($FW -like "0" ) {$FW = "Disabled"}

        }

catch {$FW = "Can not check Status"}


$OS = Get-WmiObject -ClassName Win32_OperatingSystem -ComputerName $ComputerName | select -Property *

$Uptime = (Get-Uptime -ComputerName $ComputerName | Out-String).Trim() 

$HotFix = (Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName $ComputerName -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object HotFixId,InstalledOn -First 3 | Out-String).Trim() 

# $Installed = (Get-WmiObject -Class Win32_Product -ComputerName $ComputerName -ErrorAction SilentlyContinue | select Name,Version | Out-String).Trim() 

$AntiVirus = Get-WmiObject -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ComputerName $ComputerName -ErrorAction SilentlyContinue

$LocalADmin = (Get-localadmins -ComputerName $ComputerName -ErrorAction SilentlyContinue | Out-String).Trim() 

$HardwareTYPE = Get-Laptop -ComputerName $ComputerName 

$OpenPorts= (testPorts -ComputerName $ComputerName |Out-String).Trim()

$Bitlocker = get-wmiobject -ComputerName $ComputerName -namespace root\CIMv2\Security\MicrosoftVolumeEncryption -class Win32_EncryptableVolume -ErrorAction SilentlyContinue |select -Expand ProtectionStatus
 
#0 = PROTECTION OFF
#1 = PROTECTION ON
#2 = The volume protection status cannot be determined. This can be caused by the volume being in a locked state.

If ($Bitlocker -eq "2"){$Bitlocker = "Locked by Bitlocker"}
Elseif ($Bitlocker -eq "1"){$Bitlocker = "Encrypted"}
Else{$Bitlocker = "Not Encrypted"}


# Testing if PowerShell Commandline Audting is Enabled 
Try{
    if ([bool](Get-RegistryValueData -RegistryHive LocalMachine -RegistryKeyPath Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit -ComputerName $ComputerName -ErrorAction SilentlyContinue -ValueName ProcessCreationIncludeCmdLine_Enabled).RegistryValueData){
        $PS_cmd_Audit = "Enable"
    } else {

        $PS_cmd_Audit = "Disable"
    }
}
Catch{
    $PS_cmd_Audit = "Uknown"
}


#Check If Connection via RDP allowed to pc

Try{
    if ([bool](Get-RegistryValueData -RegistryHive LocalMachine -RegistryKeyPath "System\CurrentControlSet\Control\Terminal Server" -ErrorAction SilentlyContinue -ValueName fDenyTSConnections -ComputerName $ComputerName).RegistryValueData)
    {
        $RDP = "Deny"
    } else {
        $RDP = "Allow" 
    }
}

Catch{
    $RDP = "Unknown"
}


# Windows Scripting Host (WSH) & Control Scripting File Extensions

Try{
    $ressh = (Get-RegistryValueData -RegistryHive LocalMachine -RegistryKeyPath 'Software\Microsoft\Windows Script Host\Settings' -ValueName "Enabled" -ComputerName $ComputerName -ErrorAction SilentlyContinue).RegistryValueData
    if ($ressh -eq $null){
        $WSH = "WSH key does not exist."
    } else {
        if ($ressh){
           $WSH = "Enabled"
        } else {
            $WSH = "Disabled"
        }
    }
}
Catch{
    $WSH = "Testing for Windows Scripting Host (WSH) failed."
}

     [PSCustomObject]@{
        PCName = $ComputerName
        OS = $OS.Caption
        OsVersion = $OS.Version
        BuildNumber = $OS.BuildNumber
        Uptime = $Uptime
        HotFixId = $HotFix
        Antivirus = $AntiVirus
        LocalAdmin = $LocalADmin
        Bitlocker = $Bitlocker
        DomainFWEnabled = $FW
        SMB1Status = $SMB
        PS_cmd_Audit = $PS_cmd_Audit
        RDP_From_Remote = $RDP
        WSH = $WSH
        HardwareType =$HardwareTYPE
        OpenPorts= $OpenPorts

        }| Select-Object PCName,OS,OsVersion,BuildNumber,Uptime,HotFixId,Antivirus,LocalAdmin,Bitlocker,DomainFWEnabled,SMB1Status,PS_cmd_Audit,RDP_From_Remote,WSH,HardwareType,OpenPorts | Export-Csv "C:\Users\$env:USERNAME\Desktop\Finish.csv" -Append -NoTypeInformation

        }

        Else 

        {Write-Host " $ComputerName Not Reacheble" -BackgroundColor Red}



 $os = $null
 $HotFix = $null
 $uptime = $null
 $Installed = $null
 $AntiVirus = $null
 $LocalADmin = $null
 $Bitlocker = $null
 $Fw = $null
 $check = $null
 $SMB = $null
 $RDP = $null
 $WSH = $null
 $PS_cmd_Audit = $null
 $HardwareTYPE = $null
 $OpenPorts = $null

}
     
