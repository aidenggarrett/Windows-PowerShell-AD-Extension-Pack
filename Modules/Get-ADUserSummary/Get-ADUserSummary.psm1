<#
    .Synopsis
    Retrieves a summary of an AD account
    .Description
    The Get-ADUserSummary will query the specified domain controller and retrieve the Display Name, Canonical Name, Employee Type,
    Account Expiration Date, Email Address, Mailbox Database and AD Group Membership.
    Due to a bug in a key Microsoft Command (Get-ADPrincipalGroupMember), we query the Global Catalog for the AD Group Membership Names.
    It takes a little longer, but looks far nicer!
    .Notes
    NAME: Get-ADUserSummary
    AUTHOR: Aiden Garrett
    GITHUB: https://github.com/aidenggarrett
    
    #Requires -Version 1
    #Requires -Modules ActiveDirectory
#>
Function Get-ADUserSummary
    {
    [CmdletBinding(SupportsShouldProcess=$True)]
    Param(
        
        # $Identity
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [string]$Identity,

        # Domain Controller
        [Parameter(Mandatory=$false,
                    ValueFromPipeline=$true,
                    Position=1)]
        [string]$Server

    )

        # Populate $Server if it's equal to null
        #if ( $Server -eq $null ) { $Server = (Get-ADDomainController -Discover -Service "GlobalCatalog").Name }

        #Retrieve AD information

        Write-Verbose "Retrieving Basic AD Details"

        $DisplayName = (Get-ADUser $Identity -Server $Server -Properties DisplayName).DisplayName
        $CanonicalName = (Get-ADUser $Identity -Server $Server -Properties CanonicalName).CanonicalName
        $EmployeeType = (Get-ADUser $Identity -Server $Server -Properties EmployeeType).EmployeeType
        $AccountExpires = (Get-ADUser $Identity -Server $Server -Properties AccountExpirationDate).AccountExpirationDate
        $EmailAddress = (Get-ADUser $Identity -Server $Server -Properties EmailAddress).EmailAddress

        #Retrieve Mailbox Database

        Write-Verbose "Retrieving Mailbox Database"

        $tmpMDB = (Get-ADUser $Identity -Properties msExchRecipientTypeDetails -Server $Server).msExchRecipientTypeDetails
        if ($tmpMDB -eq '2147483648' ) { $Database = 'Exchange Online' } else { 
           if ($tmpMDB -eq '1') { $Database = (Get-AdUser $Identity -Server $Server -Properties homeMDB).homeMDB.split(",=")[1] }
                else { $Database = 'N/A' }
                }

        # Retrieve AD Group Membership

        Write-Verbose "Retrieving AD Group Membership via the Global Catalog"

        $tmpMember = (Get-ADUser $Identity -Properties MemberOf -Server $Server).MemberOf
        $ADGroupMembership = $tmpMember | foreach {(Get-ADGroup $_ -Server $Server":3268" -Properties Name).Name} | Sort-Object

        # Write information to console

        Write-Verbose "AD Account Summary"

        Write-Host "Display Name:" $DisplayName
        Write-Host "OU:" $CanonicalName
        Write-Host "Username:" $Identity
        Write-Host "Employee Type:" $EmployeeType
        Write-Host "Account Expiration Date:" $AccountExpires
        Write-Host "Email Address:" $EmailAddress
        Write-Host "Database:" $Database
        Write-Host "AD Group Membership:"
        $ADGroupMembership
}