# CORP - Disabled Accounts Requiring Deletion
#
# Author: Aiden Garrett
# Company: Computacenter
#
# Revision: v2.3
# Date: 16/02/2018
#
# Lists disabled accounts in preperation for deletion
#
# Version 2 Improvements:
# Exports EmployeeType, Database and OU
#
# Version 2.1;
# Amended Name for DisplayName
#
# Version 2.2;
# Ignores accounts changed within the last 1 month
#
# Version 2.3;
# Amended Mailbox & Database Information
#

#Requires -Version 3
Import-Module ActiveDirectory -ErrorAction Inquire
#Requires -Modules ActiveDirectory

# Various variables
$DC = "cor-wsw-dc10"
# $Creds = Get-Credential
$CSVOutput = "C:\Scratch\CORP - Disabled Accounts.csv"
$Subject = "CORP - Disabled Accounts"
$SMTPServer = "smtp.clarks.com"
$TimeSpan = (Get-Date).AddMonths(-1)

# Create Output Array

$OutCSV = @()

# Get Usernames of users to be deleted

$ADUsers = Get-ADUser -Filter 'Enabled -eq $false -and Description -like "Disabled*"' | Select-Object -ExpandProperty samAccountName

# For each username, get further details and create an object

$ADUsers | ForEach-Object {
    $DisplayName = (Get-ADUser $_ -Server $DC -Properties DisplayName).DisplayName
    $samAccountName = (Get-ADUser $_ -Server $DC).samAccountName
    $Description = (Get-ADUser $_ -Server $DC -Properties Description).Description
    $DateDisabled = Get-ADUser $_ -Server $DC | Get-ADReplicationAttributeMetadata -server $DC |
        Where-Object {$_.AttributeName -like "UserAccountControl"} | Select-Object -ExpandProperty lastoriginatingchangetime
    $EmployeeType = (Get-ADUser $_ -Server $DC -Properties EmployeeType).EmployeeType
    $UPN = (Get-ADUser $_ -Server $DC).UserPrincipalName

    # Retrieve OU Information

    Write-Verbose "Retrieving Organisational Unit"

    $CanonicalName = (Get-ADUser $_ -Server $DC -Properties CanonicalName).CanonicalName
    $OU = $CanonicalName -replace "$DisplayName$",""

    #Retrieve Mailbox Database

    Write-Verbose "Retrieving Mailbox Database"

    $tmpMDB = (Get-ADUser $_ -Properties msExchRecipientTypeDetails -Server $DC).msExchRecipientTypeDetails
    if ($tmpMDB -eq '2147483648' ) { $Database = 'Exchange Online' } else {
       if ($tmpMDB -eq '1') { $Database = (Get-AdUser $_ -Server $DC -Properties homeMDB).homeMDB.split(",=")[1] }
            else { $Database = 'N/A' }
            }

    $Output = New-Object psobject
    $Output | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
    $Output | Add-Member -MemberType NoteProperty -Name samAccountName -Value $samAccountName
    $Output | Add-Member -MemberType NoteProperty -Name UniversalPrincipalName -Value $UPN
    $Output | Add-Member -MemberType NoteProperty -Name DateDisabled -Value $DateDisabled
    $Output | Add-Member -MemberType NoteProperty -Name Description -Value $Description
    $Output | Add-Member -MemberType NoteProperty -Name EmployeeType -Value $EmployeeType
    $Output | Add-Member -MemberType NoteProperty -Name OU -Value $OU
    $Output | Add-Member -MemberType NoteProperty -Name Database -Value $Database

    # Add the newly created object to our array

    $OutCSV += $Output

    }

# Export our array to a CSV file

$OutCSV | Where-Object {$_.DateDisabled -lt $TimeSpan}  | Sort-Object DateDisabled | Export-Csv $CSVOutput -NoTypeInformation

<#

# Attach our CSV and send it in an email

Send-MailMessage -From "Garrett, Aiden <aiden.garrett@clarks.com>" -To "Garrett, Aiden <aiden.garrett@clarks.com>", "CC-System-Alerts <cc-system-alerts@clarks.com>" `
    -Subject "$Subject" -Body "Disabled Accounts Requiring Deletion" -Attachments $CSVOutput -SmtpServer $SMTPServer

#>