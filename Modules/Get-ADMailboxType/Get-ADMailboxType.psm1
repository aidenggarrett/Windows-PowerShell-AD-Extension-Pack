﻿<#
    .Synopsis
    Retrieves a the mailbox type of an AD account
    .Description
    The Get-ADMailboxType will query the specified domain controller and retrieve the mailbox type. It will then interpret the value in to a name.
    .Notes
    NAME: Get-ADMailboxType
    AUTHOR: Aiden Garrett
    GITHUB: https://github.com/aidenggarrett

    #Requires -Version 1
    #Requires -Modules ActiveDirectory
#>
Function Get-ADMailboxType
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

        # Recipient Type Hash Table
        $RecipientTypeTable = [ordered]@{
            "1" = "User Mailbox"
            "2" = "Linked Mailbox"
            "4" = "Shared Mailbox"
            "8" = "Legacy Mailbox"
            "16" = "Room Mailbox"
            "32" = "Equipment Mailbox"
            "64" = "Mail Contact"
            "128" = "Mail-enabled User"
            "256" = "Mail-enabled Universal Distribution Group"
            "512" = "Mail-enabled non-Universal Distribution Group"
            "1024" = "Mail-enabled Universal Security Group"
            "2048" = "Dynamic Distribution Group"
            "4096" = "Mail-enabled Public Folder"
            "8192" = "System Attendant Mailbox"
            "16384" = "Mailbox Database Mailbox"
            "32768" = "Across-Forest Mail Contact"
            "65536" = "User"
            "131072" = "Contact"
            "262144" = "Universal Distribution Group"
            "524288" = "Universal Security Group"
            "1048576" = "Non-Universal Group"
            "2097152" = "Disabled User"
            "4194304" = "Microsoft Exchange"
            "2147483648" = "Remote User Mailbox"
            "8589934592" = "Remote Room Mailbox"
            "17179869184" = "Remote Equipment Mailbox"
            "34359738368" = "Remote Shared Mailbox"
        }

        # Populate $Server if it's equal to null
        #if ( $Server -eq $null ) { $Server = (Get-ADDomainController -Discover -Service "GlobalCatalog").Name }

        $RecipientTypeValue = ((Get-ADUser -Identity $Identity -Server $Server -Properties msExchRecipientTypeDetails).msExchRecipientTypeDetails)

        # Output
        $Output = [ordered]@{
            "Identity" = ((Get-ADUser -Identity $Identity -Server $Server).Name)
            "MailboxType" = $RecipientTypeTable["$RecipientTypeValue"]
        }

        $Output

}