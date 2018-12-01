<#
    .Synopsis
    Retrieves further details about a given AD Group
    .Description
    The Get-ADGroupMemberDetail will query the specified domain controller and retrieve the Display Name, samAccountName, Job Title,
    and Email Address for each member of the group. It is also recursive, and will query each sub-group where applicable.
    .Notes
    NAME: Get-ADGroupMemberDetail
    AUTHOR: Aiden Garrett
    GITHUB: https://github.com/aidenggarrett
    
    #Requires -Version 1
    #Requires -Modules ActiveDirectory
#>
Function Get-ADGroupMemberDetail
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
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$true,
                    Position=1)]
        [string]$DC

    )
    
    Get-ADGroupMember $GroupName -Recursive -Server $DC | Sort-object name | ForEach-Object {
        Get-ADUser -Identity $_ -Properties Title, emailAddress -Server $DC":3268" | Select-Object name, SamAccountName, Title, EmailAddress
    } | Export-Csv $CSVOutput -NoTypeInformation

}
