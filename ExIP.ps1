<#################################################################
    .NAME
        ExIP.ps1

    .SYNOPSIS
        External IP lookup script

    .DESCRIPTION
        Lookup external IPv4 and IPv6 addresses from IPInfo.io.
        Now features full validation of bogons, RFC 1918 space, and reserved IP filtering.
        This script will accept any number of IPs submitted to it as a string and sort based on unique values.

        This script performs the following:
        * Validates user input via console or file for correct IPv4 or IPv6 Address format
        * Validates input contains only non-RFC1918 IPv4 and non-Reserved IPv6 Addresses
        * Populates values from the correlation to standard io or logging if specified.

    .NOTES
        Name:           ExIP.ps1
        Author:         Ben Leedham
        Title:          Security Engineer
        Date Created:   09/14/2015
        Last Modified:  04/02/2019
        License:        MIT License, Copyright (c) 2015, 2019 Ben Leedham

    .EXAMPLE
        C:\ExIP.ps1 -ip "8.8.8.8" -export

    .REFERENCE
        Reference included for RFC compliant IPv6 matching Regular Expression
        https://www.powershelladmin.com/wiki/PowerShell_.NET_regex_to_validate_IPv6_address_(RFC-compliant)
	
    .CITATIONS
        Original RFC 2373 IPv6 Perl regex by Salvador Fandino, ported to PowerShell by Joakim Borger Svendsen, Svendsen Tech.

############################################>
Param(
[string]$ip,
[switch]$list,
[switch]$export,
[string]$path = $($(Resolve-Path .\).Path + "\ExIPs\"),
$ExecutionPolicy = $(Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Scope CurrentUser),
$VerbosePreference = $("silentlycontinue"),
$ErrorActionPreference = $("silentlycontinue")
)

Function Run-Main($ip)
{
    [string]$regv4 = "(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
    [array]$ipv4 = $($ip | select-string -Pattern $regv4 -AllMatches | % { $_.Matches.Groups } | where{$_.value}).value | select -Unique

    [string]$regv6 = ':(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))'
    [array]$ipv6 = $($ip | select-string -Pattern $regv6 -AllMatches | % { $_.Matches.Groups } | where{$_.value}).value | select -Unique

    Foreach($ia in $ipv4)
    {
        try
        {
            $ia = [ipaddress]$ia
            [array]$io = $ia.IPAddressToString -split "\."
            if([int]$io[0] -eq "10"){continue}
            elseif([int]$io[0] -eq "127"){continue}
            elseif([int]$io[0] -eq "128" -and [int]$io[1] -eq "0"){continue}
            elseif([int]$io[0] -eq "169" -and [int]$io[1] -eq "254"){continue}
            elseif([int]$io[0] -eq "172" -and [int]$io[1] -ge "16" -and [int]$io[1] -le "32"){continue}
            elseif([int]$io[0] -eq "191" -and [int]$io[1] -eq "255"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "0" -and [int]$io[2] -eq "0"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "0" -and [int]$io[2] -eq "2"){continue}
            elseif([int]$io[0] -eq "192" -and [int]$io[1] -eq "168"){continue}
            elseif([int]$io[0] -eq "198" -and [int]$io[1] -eq "18"){continue}
            elseif([int]$io[0] -eq "198" -and [int]$io[1] -eq "19"){continue}
            elseif([int]$io[0] -eq "223" -and [int]$io[1] -eq "255" -and [int]$io[2] -eq "255"){continue}
            elseif([int]$io[0] -gt "224"){continue}
            elseif([int]$io[0] -eq "0"){continue}
            else
            {
                $j = Invoke-RestMethod -Uri "http://ipinfo.io/$($ia.IPAddressToString)/json" -Method "Get"
                Write-Output $j
                if($export.IsPresent){$global:array += $j}
            }
        }
        catch{}
    }
    Foreach($ib in $ipv6)
    {
        try
        {
            $ib = [ipaddress]$ib
            [array]$ih = $ib -split ":"
            if([int]$ih[0] -eq "fe80"){continue}
            elseif([int]$ih[0] -eq "0000"){continue}
            elseif([int]$ih[0] -eq "0200"){continue}
            elseif([int]$ih[0] -eq "3ffe"){continue}
            elseif([int]$ih[0] -eq "2001" -and [int]$ih[1] -eq "db8"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "e000"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "7f00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "0000"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "ff00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "0a00"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "ac10"){continue}
            elseif([int]$ih[0] -eq "2002" -and [int]$ih[1] -eq "c0a8"){continue}
            elseif([int]$ih[0] -eq "fc00"){continue}
            elseif([int]$ih[0] -eq "fec0"){continue}
            elseif([int]$ih[0] -eq "ff00"){continue}
            else
            {
                $j = Invoke-RestMethod -Uri "http://ipinfo.io/$($ib.IPAddressToString)/json" -Method "Get"
                Write-Output $j
                if($export.IsPresent){$global:array += $j}
            }
        }
        catch{}
    }
} 

# Running main function with conditional logic and outputs
if($ip -ne "")
{
    if($export.IsPresent)
    {
        [array]$global:array = @()
        [string]$date = $(Get-Date).ToString("yyyy-MM-dd-hhmm")
        [string]$logging = "$path\Logs\ExIPs-$date.csv"
        New-Item -Path $logging -ItemType "File" -Force | Out-Null
        Run-Main -ip $ip
        $global:array | Export-Csv -NoTypeInformation -Path $logging
        Remove-Variable -Name $global:array -ErrorAction "SilentlyContinue"
    }
    else
    {
        Run-Main -ip $ip
    }
}

if($list.IsPresent)
{
    [string]$data = $(Get-Content -Path "$path\Libraries\ExIPfile.txt" | Out-String)
    if($export.IsPresent)
    {
        [array]$global:array = @()
        [string]$date = $(Get-Date).ToString("yyyy-MM-dd-hhmm")
        [string]$logging = "$path\Logs\ExIPs-$date.csv"
        New-Item -Path $logging -ItemType "File" -Force | Out-Null
        Run-Main -ip $data
        $global:array | Export-Csv -NoTypeInformation -Path $logging
        Remove-Variable -Name $global:array -ErrorAction "SilentlyContinue"
    }
    else
    {
        Run-Main -ip $data
    }
}
