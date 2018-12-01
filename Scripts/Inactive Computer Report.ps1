# Reports on computers inactive within a given timeframe.
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
    $CSVName = $CSVFileName + " - " + $CSVDate +".csv" # This would become "computers - 20181201.csv"
    $CSVOutput = $CSVPath+$CSVName

# Email Variables
    $EmailFrom = # Sender's email address
    $EmailTo = # Recipient Addresses. For multiple, separate them with a comma.
    $EmailSubject = # Subject
    $EmailBody = # Insert email comments here.
    $SMTPServer = # SMTP Server

# Get computer accounts who haven't logged in the last $TimeSpan, where $TimeSpan is the number of days to query

$ADComputersTemp = Search-ADAccount -ComputersOnly -AccountInactive -TimeSpan $TimeSpan -Server $DC | Select-Object -ExpandProperty Name

$ADComputers = @()

$ADComputersTemp | ForEach-Object {

    $Enabled = (Get-ADComputer -Identity $_ -Server $DC).Enabled
    $LastLogonDate = (Get-ADComputer -Identity $_ -Server $DC -Properties LastLogonDate).LastLogonDate
    $IPv4 = (Resolve-DnsName $_ -Type A -Server $DC).IPAddress

    $CanonicalName = (Get-ADComputer $_ -Server $DC -Properties CanonicalName).CanonicalName
    $OU = $CanonicalName -replace "$_$",""

    $OS = (Get-ADComputer $_ -Server $DC -Properties OperatingSystem).OperatingSystem

    $Output = New-Object psobject
    $Output | Add-Member -MemberType NoteProperty -Name 'Name' -Value $_
    $Output | Add-Member -MemberType NoteProperty -Name 'Enabled' -Value $Enabled
    $Output | Add-Member -MemberType NoteProperty -Name 'Last Logon Date' -Value $LastLogonDate
    $Output | Add-Member -MemberType NoteProperty -Name 'IP Address' -Value $IPv4
    $Output | Add-Member -MemberType NoteProperty -Name 'OU' -Value $OU
    $Output | Add-Member -MemberType NoteProperty -Name 'OS' -Value $OS

    $ADComputers += $Output

}

# Export our array to a CSV file

$ADComputers | Sort-Object Name | Export-Csv $CSVOutput -NoTypeInformation

# Attach our CSV and send it in an email

Send-MailMessage -From $EmailFrom -To $EmailTo `
    -Subject "$EmailSubject" -Body $EmailBody -Attachments $CSVOutput -SmtpServer $SMTPServer