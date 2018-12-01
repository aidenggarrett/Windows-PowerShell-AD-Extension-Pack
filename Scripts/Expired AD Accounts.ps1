# Reports on expired user accounts.
#
# AUTHOR: Aiden Garrett
# GITHUB: https://github.com/aidenggarrett
#

#Requires -Version 3
Import-Module ActiveDirectory -ErrorAction Inquire
#Requires -Modules ActiveDirectory

# Variables
    $TimeSpan = # Time span, in days
    $DC = # Domain Controller

# CSV Variables
    $CSVPath = # Output Location
    $CSVDate = Get-Date -Format yyyyMMdd
    $CSVFileName = # File Name 
    $CSVName = $CSVFileName + " - " + $CSVDate +".csv" # This would become "computers - 20181201.csv"
    $CSVOutput = $CSVPath+$CSVName

# Email Variables
    $EmailFrom = # Sender's email address
    $EmailTo = # Recipient Addresses. For multiple, separate them with a comma.
    $EmailSubject = # Subject
    $EmailBody = # Insert email comments here.
    $SMTPServer = # SMTP Server

# Misc Variables
    $TimeSpan = (Get-Date).AddMonths(-1)

# Create Output Array

$OutCSV = @()

# Get Usernames of users to be deleted

$ADUsers = Search-ADAccount -AccountExpired -Server $DC | Select-Object -ExpandProperty samAccountName

# For each username, get further details and create an object

$ADUsers | ForEach-Object {
    $DisplayName = (Get-ADUser $_ -Server $DC).DisplayName
    $samAccountName = (Get-ADUser $_ -Server $DC).samAccountName
    $Description = Get-ADUser $_ -Properties Description -Server $DC | Select-Object -ExpandProperty Description
    $Enabled = Get-ADUser $_ -Server $DC | Select-Object -ExpandProperty Enabled
    $Expiry = Get-ADUser $_ -Server $DC -Properties AccountExpirationDate | Select-Object -ExpandProperty AccountExpirationDate
    $LastLogon = Get-ADUser $_ -Server $DC -Properties LastLogonDate | Select-Object -ExpandProperty LastLogonDate

    $Output = New-Object psobject
    $Output | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
    $Output | Add-Member -MemberType NoteProperty -Name samAccountName -Value $samAccountName
    $Output | Add-Member -MemberType NoteProperty -Name Enabled -Value $Enabled
    $Output | Add-Member -MemberType NoteProperty -Name ExpiryDate -Value $Expiry
    $Output | Add-Member -MemberType NoteProperty -Name LastLogonDate -Value $LastLogon
    $Output | Add-Member -MemberType NoteProperty -Name Description -Value $Description
    
    
    # Add the newly created object to our array

    $OutCSV += $Output

    }

# Export our array to a CSV file

$OutCSV | Where-Object {$_.Description -notlike "Disabled*" -and $_.ExpiryDate -lt $TimeSpan} | Sort-Object ExpiryDate | Export-Csv $CSVOutput -NoTypeInformation

# Attach our CSV and send it in an email

Send-MailMessage -From $EmailFrom -To $EmailTo `
    -Subject $EmailSubject -Body $EmailBody -Attachments $CSVOutput -SmtpServer $SMTPServer