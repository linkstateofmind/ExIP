# ExIP

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
