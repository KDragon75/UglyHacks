<#
.DESCRIPTION
    This tool is to assist in preparing for one drive migration and for post migration taskes.
.PARAMETER UserListCSV
    Path to the list of users that have home folders and have been migrated or are to be migrated.
.PARAMETER WorkingDir
    Path to user home folders.
.PARAMETER EnableInheritance
    Enable inheritance for all users in the UserListCSV at all folder levels while preserving any explicitly defined permissions.
    If no user list is provided, enhertance is enabled on all folders with in the working directory
.PARAMETER Set-ReadOnly
    Sets all users in the UserListCSV to read, list, and execute at all levels where the user is present at the top level. This only works when a user list is provided.
.PARAMETER Log
    When set, enables logging. Logs are saved to the same location as the script.

.EXAMPLE
    Assist-OneDriveMigration -EnableInheritance -UserListCSV c:\UserList.csv -WorkingDir \\Server\Users\ -log
    This will attempt to enable inheritance for all users folders at all levels listed in c:\UserList.csv in the directory \\Server\Users\ and write a log of the work done.
.EXAMPLE
    Assist-OneDriveMigration -SetReadOnly -UserListCSV c:\UserList.csv -WorkingDir \\Server\Users\
    This will attempt to set users to Read and Execute for folders at all levels where the user is listed on the top level user folder. This will be performed against all users listed in c:\UserList.csv in the directory \\Server\Users\.
.EXAMPLE
    Assist-OneDriveMigration -UserListCSV c:\UserList.csv -WorkingDir \\Server\Users\ -log
    This will only scan for matches based on ACLs on the folders and log the results. Nothing will be modifyed.

.NOTES
    Author: Curtis Grice
    Date:   September 15, 2020
    Caution, this script is provided as is with no implied correctness or suitability for use in any environment. Use at your own risk!   
#>
function Assist-OneDriveMigration {

    [CmdletBinding()]

    Param (
        [Parameter()]
        [ValidateScript({
            If ( Test-Path $_ ){
                $true
            } else {
                throw "The file $_ does not seem to exist."
            }
        })]
        [String]$UserListCSV,

        [Parameter(Mandatory)]
        [ValidateScript({
            If ( Test-Path $_ ){
                $true
            } else {
                throw "The path $_ does not seem to exist."
            }
        })]
        [String]$WorkingDir,

        [Parameter()]
        [Switch]$EnableInheritance,

        [Parameter()]
        [Switch]$SetPermission,

        [Parameter()]
        [Switch]$AuditOnly,

        [Parameter()]
        [Switch]$Log
    )

    # Enable logging if switch set
        If ($Log.IsPresent -eq $true) {
        $script:LogEn = $true
        $script:StartTime = (get-date -f yyyy-MM-dd-HHmmss)
    }

    $script:FolderAcls = @()
    

    Write-Log "Info - Using $UserListCSV as user list and $WorkingDir as working directory..."

    # Load top level ACLs into memory for fasted searching and time it
    $Timer = (Measure-Command -Expression {
        Get-ChildItem $WorkingDir | foreach {
            $FolderAcls += Get-Acl -Path $_.FullName
        }
    }).TotalSeconds
    Write-Log ("Info - Loaded " + $FolderAcls.Count + " ACLs in $Timer Seconds.")

    if ($UserListCSV -ne '') {
        # Load the user list and start working
        Import-Csv -Path $UserListCSV | ForEach {
        
            #Lookup AD accounts by email column in the CSV---------------------------
            #$email = $_.'Email Address'
            $name = $_.SamAccountName

          #Use SAM from CSV----------------------------------------------------------
            If ($ADUser = Get-ADUser -Identity $name) {
          #OR
          #Use email address---------------------------------------------------------
            #If ($ADUser = Get-ADUser -Filter {EmailAddress -like $email}) {
                Write-Log "Info - Found AD user $ADUser for $email"
            
                # Build a list of top level folders that a user has access to
                $TargetFolders = Find-UserFolderByACL $ADUser
        
                # Log the found folders
                If ($TargetFolders.Count -gt 0) {
                    $TargetFolders | ForEach { Write-Log ("Info - Found " + $_.FullName + " for user " + $ADUser.SamAccountName + ".") }
        
                    #If set, call the Restore-Inheritance function
                    If ($EnableInheritance.IsPresent) { $TargetFolders | ForEach {Restore-Inheritance -TargetFolders $_} }

                    #If set, call the Set-UserPermission function and set permissions to ReadAndExecute
                    If ($SetPermission.IsPresent) { $TargetFolders | ForEach {Set-UserPermission -User $ADUser -Permission 'ReadAndExecute' -TargetFolders $_} }

                    #If set, Run-Audit and log if users are set to read only at the top level
                    If ($AuditOnly.IsPresent) { $TargetFolders | ForEach {Run-Audit -User $ADUser -TargetFolders $_} }

                } else {
                    Write-Log ("Warning - No folders found for " + $ADUser.SamAccountName + ".")
                }
            } else {
                Write-Log "Warning - No AD user found for $name"
            }
        }
    } else {

        # If no userlist is provided, just set inheritance for all folders at all levels under the working directory
        If ($EnableInheritance.IsPresent) { Get-ChildItem -Path $WorkingDir | ForEach {Restore-Inheritance -TargetFolders $_} }
    }
    Write-Log ("Info - Done!")
}

# Logging function so we know what was done and if there were errors.
Function Write-Log ($msg) {
    $LogLine = (get-date).ToString() + " - $msg"
    Write-Output $LogLine 
    #
    If ($LogEn -eq $true) {
        Add-Content -Path ("$PSScriptRoot\" + ($PSCommandPath | Split-Path -Leaf).TrimEnd('.ps1') + "-$StartTime.log") -Value $LogLine # Write to the logfile based on the scripts location, default is system32 if not running from a script file
    }
}

# Builds the list of top level folders a user has access to and returns that array of folders.
Function Find-UserFolderByACL ($User) {

    # For each ACL entry (loaded into memory) find all folders that $User has access to based on SID and return the folder as a filesystem object
    $FolderList = @()
    $FolderAcls | foreach {
        if (($_).Access | Where-Object { ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value) -eq $User.SID }) {
            $FolderList += Get-Item $_.Path
        }
    }
    Return $FolderList
}

# Restore Inheritance at the top user folder level, then at all sub folders as well. Note, this preserves any explicit permissisons
Function Restore-Inheritance ($TargetFolders) {
    $error = ''
    ForEach ($TargetFolder in $TargetFolders) {
        Try {
            $acl = Get-Acl -Path $TargetFolder.FullName -ErrorAction SilentlyContinue
        } Catch {
            Write-Log $("Error - Unable to read ACLs for " + $TargetFolder.FullName + ". " + $_.Exception.Message)
        }
        If ($acl.AreAccessRulesProtected -eq $true) {
            $acl.SetAccessRuleProtection($false,$true)
            Try {
                ($TargetFolder).SetAccessControl($acl)
                Write-Log ("Info - Enabled inheritance on " + $TargetFolder.FullName)
            } Catch {
                Write-Log ("Error - Unsuccessful setting inheritance on " + $TargetFolder.FullName + " " + $_.Exception.Message)
            }
        }
        $FolderAcls = @()
        $ChildFolders = Get-ChildItem -Path $TargetFolder.FullName -Recurse -Attributes d
        ForEach ($Folder in $ChildFolders) {
            Try {
                $FolderAcls += Get-Acl -Path $Folder.FullName -ErrorAction SilentlyContinue
            } Catch {
                Write-Log $("Error - Unable to read ACLs for " + $Folder.FullName + ". " + $_.Exception.Message)
            }
        }
        $FolderAcls | Where-Object { $_.AreAccessRulesProtected -eq $true} | ForEach {
            $_.SetAccessRuleProtection($false,$true)
            Try {
                (Get-Item -Path $_.Path).SetAccessControl($_)
                Write-Log ("Info - Enabled inheritance on " + $_.Path)
            } Catch {
                Write-Log ("Error - Unsuccessful setting inheritance on " + $_.Path + " " + $_.Exception.Message)
            }
        }
    }
}

# Sets top level folders to ReadAndExecute, then iterates through all subfolders and sets ReadAndExecute permissisons for all explicit permissisons for the user
Function Set-UserPermission ($User, $Permission, $TargetFolders) {

    ForEach ($TargetFolder in $TargetFolders) {
        $acl = Get-ACL -Path $TargetFolder.FullName
        $acl.PurgeAccessRules($User.SID)
        Try {    
            ($TargetFolder).SetAccessControl($acl)
            Write-Log ("Info - Purged " + $User.SamAccountName + " ACE from " + $TargetFolder.FullName + ".")
        } Catch {
            Write-Log ("Error - Unsuccessful purging " + $User.SamAccountName + " ACE from " + $TargetFolder.FullName + ". " + $_.Exception.Message)
        }

        $acl = Get-ACL -Path $TargetFolder.FullName
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($User.SamAccountName, $Permission, 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.SetAccessRule($AccessRule)
        Try {
            ($TargetFolder).SetAccessControl($acl)
            Write-Log ("Info - Granted " + $User.SamAccountName + " $Permission to " + $TargetFolder.FullName + ".")
        } Catch {
            Write-Log ("Error - Unsuccessful setting " + $User.SamAccountName + " to $Permission on " + $TargetFolder.FullName + ". " + $_.Exception.Message)
        }

        $ChildFolders = Get-ChildItem -Path $TargetFolder.FullName -Recurse -Attributes d
        ForEach ($Folder in $UserFolders) {
            $acl = Get-ACL -Path $Folder.FullName
            if ( ($acl.Access | Where-Object { ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value) -eq $User.SID }) -and ($acl.Access | Where-Object { ($_.IsInherited) } -eq $false) ) {
                $acl.PurgeAccessRules($User.SID)
                Try {
                    ($Folder).SetAccessControl($acl)
                    Write-Log ("Info - Purged " + $User.SamAccountName + " ACE from " + $Folder.FullName + ".")
                } Catch {
                    Write-Log ("Error - Unsuccessful purging " + $User.SamAccountName + " ACE from " + $Folder.FullName + ". " + $_.Exception.Message)
                }

                $acl = Get-ACL -Path $Folder.FullName
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($User.SamAccountName, $Permission, 'ContainerInherit, ObjectInherit', 'None', 'Allow')
                $acl.SetAccessRule($AccessRule) 
                Try {
                    ($Folder).SetAccessControl($acl)
                    Write-Log ("Info - Granted " + $User.SamAccountName + " $Permission to " + $Folder.FullName + ".")
                } Catch {
                    Write-Log ("Error - Unsuccessful setting " + $User.SamAccountName + " to $Permission on " + $Folder.FullName + ". " + $_.Exception.Message)
                }
            }
        }
    }
}

Function Run-Audit ($User, $TargetFolders) {

    ForEach ($TargetFolder in $TargetFolders) {
        Try { $acl = Get-Acl -Path $TargetFolder.FullName}
        Catch { Write-Log ("Error - Unable to read ACLs for " + $TargetFolder.FullName + ".") 
            Write-Log ("Error - $error")
        }
        $FolderAce = ($acl.Access | Where-Object { ($_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value) -eq $User.SID } )
        if ($FolderAce.FileSystemRights -like '*ReadAndExecute*' ) {
            Write-Log ("Audit - " + $User.SamAccountName +  " folder " + $TargetFolder.FullName + " set to " + $FolderAce.FileSystemRights)
        } else {
            Write-Log ("Audit Notice - " + $User.SamAccountName +  " folder " + $TargetFolder.FullName + " set to " + $FolderAce.FileSystemRights)
        }
    }    
}