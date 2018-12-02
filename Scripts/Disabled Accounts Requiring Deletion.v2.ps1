# Reports on user accounts that require deleting.
# Assumes that the account description starts with the word "Disabled"
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

$ADUsers = Get-ADUser -Filter 'Enabled -eq $false -and Description -like "Disabled*"' -Server $DC | Select-Object -ExpandProperty samAccountName

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

# Attach our CSV and send it in an email

Send-MailMessage -From $EmailFrom -To $EmailTo  `
    -Subject $EmailSubject -Body $EmailBody -Attachments $CSVOutput -SmtpServer $SMTPServer