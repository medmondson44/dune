function Get-EventProps {
  [cmdletbinding()]
  Param (
    [parameter(ValueFromPipeline)]
    $event
  )
    Process {
        $eventXml = [xml]$event.ToXML()
        $eventKeys = $eventXml.Event.EventData.Data
        $Properties = @{}
        $Properties.EventId = $event.Id

        For ($i=0; $i -lt $eventKeys.Count; $i++) {
            $Properties[$eventKeys[$i].Name] = $eventKeys[$i].'#text'
        }

        [pscustomobject]$Properties
    }
}

function reverse {
 $arr = @($input)
 [array]::reverse($arr)
 $arr
}

function Get-LatestLogs {
<#
.EXAMPLE
    Get-LatestLogs -computername localhost -Logname security -MaxEvents 5 | ConvertTo-Json | Out-File -Encoding ASCII -FilePath my-security-data.json

#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$True,
               HelpMessage="Enter ComputerName")]
    [string[]]$Computername,
    #[int32]$MaxEvents=5000, got rid of max events parameter
    [string]$Logname
)
foreach ($comp in $Computername)
{
    Get-WinEvent -ComputerName $Comp -filterhashtable @{logname=$logname} | Get-EventProps | reverse
}
}

function Get-LatestLogsFromPath {
<#
.EXAMPLE
    Get-LatestLogsFromPath -Path c:\windows\system32\winevt\logs\security -MaxEvents 5 | ConvertTo-Json | Out-File -Encoding ASCII -FilePath my-security-data.json
.EXAMPLE
    Get-LatestLogsFromPath -Path D:\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx -MaxEvents 1000 | ? {$_.Eventid -eq 1 -and ($_.UTCTime -le "2020-07-19 21:19:54.467" -and $_.UTCtime -ge "2020-07-19 11:47:54.467")} |ogv
.EXAMPLE
    Get-LatestLogsFromPath -Path D:\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx -MaxEvents 1000 | ? {$_.Eventid -eq 1 -and ($_.Image -match "cmd" -or $_.Image -match "powers") -and ($_.Commandline -match "\.bat" -or $_.Commandline -match "\.cmd")} | select DateUTC,ParentImage,ParentCommandline,Image,Commandline |ogv
#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$True)]
    #[int32]$MaxEvents,got rid of max events parameter
    [string]$Path
)
    Get-WinEvent -filterhashtable @{Path=$Path} | Get-EventProps | reverse
}


function Get-LatestLogsId {
<#
.EXAMPLE
    Get-LatestLogsId -computername localhost -Logname security -id 4624 -MaxEvents 5 | ConvertTo-Json | Out-File -Encoding ASCII -FilePath my-security-data.json

#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$True,
               HelpMessage="Enter ComputerName")]
    [string[]]$Computername,
    [int32]$MaxEvents=5000,
    [string]$Logname,
    [string[]]$Id
)
foreach ($comp in $Computername)
{
    Get-WinEvent -ComputerName $Comp -filterhashtable @{logname=$logname;id=$id} -MaxEvents $MaxEvents | Get-EventProps | reverse
}
}

function Get-LatestLogsFromPathId {
<#
.EXAMPLE
    Get-LatestLogsFromPathId -Path c:\windows\system32\winevt\logs\security -id 4624 -MaxEvents 5 | ConvertTo-Json | Out-File -Encoding ASCII -FilePath my-security-data.json
.EXAMPLE
    Get-LatestLogsFromPathId -Path D:\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx -id 1 -MaxEvents 1000 | ? {$_.Eventid -eq 1 -and ($_.UTCTime -le "2020-07-19 21:19:54.467" -and $_.UTCtime -ge "2020-07-19 11:47:54.467")} |ogv
.EXAMPLE
    Get-LatestLogsFromPathId -Path D:\C\Windows\System32\winevt\logs\Microsoft-Windows-Sysmon%4Operational.evtx -id 1 -MaxEvents 1000 | ? {$_.Eventid -eq 1 -and ($_.Image -match "cmd" -or $_.Image -match "powers") -and ($_.Commandline -match "\.bat" -or $_.Commandline -match "\.cmd")} | select DateUTC,ParentImage,ParentCommandline,Image,Commandline |ogv

#>

[cmdletbinding()]
param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$True)]
    #[int32]$MaxEvents,
    [string]$Path,
    [string[]]$Id
)
    Get-WinEvent -filterhashtable @{Path=$Path;id=$id} | Get-EventProps | reverse
}

#-MaxEvents $MaxEvents ^^ inside get-winevent
#add $BackTime functionality run on scheduled task that dumps into postgresql database

Function Get-Svc {

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false,
               ValueFromPipeline=$True,
               HelpMessage="Enter Path")]
    [int32]$BackMins=180,
    [string[]]$Path,
    [string[]]$logname
)

$BackTime=(Get-Date) - (New-TimeSpan -Minutes $BackMins)
try {
$RawEvents = Get-WinEvent -Path $Path | Where-Object {$_.Id -eq 7045} #\| Where-Object {$_.TimeCreated -ge $BackTime}
}
catch {
$RawEvents = Get-WinEvent -LogName $logname | Where-Object {$_.TimeCreated -ge $BackTime} | Where-Object {$_.Id -eq 7045}
}
$RawEvents | ForEach-Object {  
    $PropertyBag = @{
        HostName = $_.MachineName
        Version=$_.Version
        EventID = $_.Id
        TimeCreated = get-date ($_.TimeCreated) -Format s
        ServiceName = $_.Properties[0].Value
        ImagePath = $_.Properties[1].Value
        ServiceType = $_.Properties[2].Value
        StartType = $_.Properties[3].Value
        AccountName = $_.Properties[4].Value
        }
        $Output = New-Object -TypeName PSCustomObject -Property $PropertyBag
    # When modifying PropertyBag remember to change Seldect-Object for ordering below
    $Output | Select-Object TimeCreated, HostName, Version, EventID, 
    ServiceName, ImagePath, ServiceType, StartType, AccountName
        }



}