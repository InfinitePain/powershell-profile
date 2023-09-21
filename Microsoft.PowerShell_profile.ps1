### PowerShell template profile 
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba
###
### This file should be stored in $PROFILE.CurrentUserAllHosts
### If $PROFILE.CurrentUserAllHosts doesn't exist, you can make one with the following:
###    PS> New-Item $PROFILE.CurrentUserAllHosts -ItemType File -Force
### This will create the file and the containing subdirectory if it doesn't already 
###
### As a reminder, to enable unsigned script execution of local scripts on client Windows, 
### you need to run this line (or similar) from an elevated PowerShell prompt:
###   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
### This is the default policy on Windows Server 2012 R2 and above for server Windows. For 
### more information about execution policies, run Get-Help about_Execution_Policies.

# Import Terminal Icons
Import-Module -Name Terminal-Icons

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so and the current host is a command line, then change to red color 
# as warning to user that they are operating in an elevated context

# Drive shortcuts
function HKLM: { Set-Location HKLM: }
function HKCU: { Set-Location HKCU: }
function Env: { Set-Location Env: }

# Set up command prompt and window title. Use UNIX-style convention for identifying 
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt { 
    if ($isAdmin) {
        "[" + (Get-Location) + "] # " 
    } else {
        "[" + (Get-Location) + "] $ "
    }
}

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()
if ($isAdmin) {
    $Host.UI.RawUI.WindowTitle += " [ADMIN]"
}
# Simple function to start a new elevated process. If arguments are supplied then 
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {   
        $argList = "& '" + $args + "'"
        Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    } else {
        Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights. 
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin


# Make it easy to edit this profile once it's installed
function Edit-Profile {
    if ($host.Name -match "ise") {
        $psISE.CurrentPowerShellTab.Files.Add($profile.CurrentUserAllHosts)
    } else {
        notepad $profile.CurrentUserAllHosts
    }
}

# We don't need these any more; they were just temporary variables to get to $isAdmin. 
# Delete them to prevent cluttering up the user profile. 
Remove-Variable identity
Remove-Variable principal

function reload-profile {
    & $profile
}

$basePath = "C:\msys64\usr\bin"
# List of program names (excluding the base path)
$UnixEssentialsForWindows = @(
    "mkdir.exe", "rmdir.exe", "ln.exe", "chown.exe",
    "chmod.exe", "dd.exe", "df.exe", "du.exe",
    "tar.exe", "less.exe", "find.exe", "grep.exe",
    "sed.exe", "awk.exe", "umount.exe", "time.exe",
    "mktemp.exe", "mknod.exe", "truncate.exe", "basenc.exe",
    "cut.exe", "tr.exe", "od.exe", "uniq.exe",
    "comm.exe", "head.exe", "join.exe", "md5sum.exe",
    "tail.exe", "wc.exe", "strings.exe", "column.exe",
    "xargs.exe", "iconv.exe", "file.exe", "sha1sum.exe", 
    "sha256sum.exe", "sha512sum.exe", "sha224sum.exe", "sha384sum.exe",
    "which.exe", "touch.exe", "split.exe", "paste.exe", 
    "env.exe", "date.exe", "whoami.exe", "tty.exe",
    "stat.exe", "seq.exe", "pr.exe", "nl.exe",
    "nohup.exe", "nice.exe", "shuf.exe", "dirname.exe",
    "basename.exe", "factor.exe", "yes.exe", "curl.exe", 
    "wget.exe", "gzip.exe", "bzip2.exe", "bzcat.exe",
    "tac.exe", "rev.exe", "printenv.exe", "locate.exe",
    "hexdump.exe", "fold.exe", "expand.exe", "expr.exe",
    "cal.exe", "patch.exe", "cmp.exe"
)

$UnixEssentialsForWindows | ForEach-Object {
    $fullPath = Join-Path -Path $basePath -ChildPath $_
    if (Test-Path $fullPath) {
        $aliasName = $_ -replace ".exe", ""
        Set-Alias -Name $aliasName -Value $fullPath
    }
}

## Final Line to set prompt
oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cobalt2.omp.json | Invoke-Expression
