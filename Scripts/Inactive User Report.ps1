# Reports on users inactive within a given timeframe.
#
# AUTHOR: Aiden Garrett
# GITHUB: https://github.com/aidenggarrett
#

# Variables
    $TimeSpan = # Time span, in days
    $DC = # Domain Controller

# CSV Variables
    $CSVPath = # Output Location
    $CSVDate = Get-Date -Format yyyyMMdd
    $CSVFileName = # File Name 
    $CSVName = $CSVFileName + " - " + $CSVDate +".csv" # This would become "users - 20181201.csv"
    $CSVOutput = $CSVPath+$CSVName

# Email Variables
    $EmailFrom = # Sender's email address
    $EmailTo = # Recipient Addresses. For multiple, separate them with a comma.
    $EmailSubject = # Subject
    $EmailBody = # Insert email comments here.
    $SMTPServer = # SMTP Server

# Misc Variables
    $ExpiryDateValue = (Get-Date).AddMonths(-1)

# Create Output Array

$OutCSV = @()

# Get Usernames of users who haven't logged in the last $TimeSpan, where $TimeSpan is the number of days to query

$ADUsers = Search-ADAccount -UsersOnly -AccountInactive -TimeSpan $TimeSpan -Server $DC | Select-Object -ExpandProperty SamAccountName

# For each username, get further details and create an object

$ADUsers | ForEach-Object {
    $DisplayName = (Get-ADUser $_ -Server $DC -Properties DisplayName).DisplayName
    $samAccountName = (Get-ADUser $_ -Server $DC).samAccountName
    $Description = Get-ADUser $_ -Properties Description -Server $DC | Select-Object -ExpandProperty Description
    $EmployeeType = Get-ADUser $_  -Properties EmployeeType -Server $DC | Select-Object -ExpandProperty EmployeeType
    $EmployeeID = Get-ADUser $_ -Properties EmployeeID -Server $DC | Select-Object -ExpandProperty EmployeeID
    $Enabled = Get-ADUser $_ -Server $DC | Select-Object -ExpandProperty Enabled
    $Created = Get-ADUser $_ -Properties WhenCreated -Server $DC | Select-Object -ExpandProperty WhenCreated
    $LastLogonDate = Get-ADUser $_ -Properties LastLogonDate -Server $DC | Select-Object -ExpandProperty LastLogonDate
    $PasswordLastSet = Get-ADUser $_ -Properties PasswordLastSet -Server $DC | Select-Object -ExpandProperty PasswordLastSet
    $Expiry = Get-ADUser $_ -Server $DC -Properties AccountExpirationDate | Select-Object -ExpandProperty AccountExpirationDate
    $UPN = (Get-ADUser $_ -Server $DC).UserPrincipalName

    $Output = New-Object psobject
    $Output | Add-Member -MemberType NoteProperty -Name DisplayName -Value $DisplayName
    $Output | Add-Member -MemberType NoteProperty -Name samAccountName -Value $samAccountName
    $Output | Add-Member -MemberType NoteProperty -Name UniversalPrincipalName -Value $UPN
    $Output | Add-Member -MemberType NoteProperty -Name Description -Value $Description
    $Output | Add-Member -MemberType NoteProperty -Name EmployeeType -Value $EmployeeType
    $Output | Add-Member -MemberType NoteProperty -Name EmployeeID -Value $EmployeeID
    $Output | Add-Member -MemberType NoteProperty -Name Enabled -Value $Enabled
    $Output | Add-Member -MemberType NoteProperty -Name Created -Value $Created
    $Output | Add-Member -MemberType NoteProperty -Name LastLogonDate -Value $LastLogonDate
    $Output | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $PasswordLastSet
    $Output | Add-Member -MemberType NoteProperty -Name ExpiryDate -Value $Expiry

    # Add the newly created object to our array

    $OutCSV += $Output

    }

# Export our array to a CSV file

$AllBarResourceAccounts = $OutCSV | Where-Object {$_.EmployeeType -ne "Resource"}
$ResourceFilter = $OutCSV | Where-Object { ( $_.EmployeeType -eq "Resource" -and $_.Enabled -eq "TRUE" ) }

$FilteredAccounts = $AllBarResourceAccounts + $ResourceFilter | Where-Object {$_.Description -notlike "Disabled*"} | Where-Object {$_.ExpiryDate -gt $ExpiryDateValue -or $_.ExpiryDate -eq $null} | Where-Object {$_.Created -lt $ExpiryDateValue}

$FilteredAccounts | Sort-Object DisplayName | Export-Csv $CSVOutput -NoTypeInformation

# Attach our CSV and send it in an email

Send-MailMessage -From $EmailFrom -To $EmailTo `
    -Subject $EmailSubject -Body $EmailBody -Attachments $CSVOutput -SmtpServer $SMTPServer