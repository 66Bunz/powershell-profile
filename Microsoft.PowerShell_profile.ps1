#region Configuration

if ([bool]([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsSystem) {
    [System.Environment]::SetEnvironmentVariable('POWERSHELL_TELEMETRY_OPTOUT', 'true', [System.EnvironmentVariableTarget]::Machine)
}

function Test-CommandExists {
    param($command)
    $exists = $null -ne (Get-Command $command -ErrorAction SilentlyContinue)
    return $exists
}

$EDITOR = if (Test-CommandExists nvim) { 'nvim' }
elseif (Test-CommandExists pvim) { 'pvim' }
elseif (Test-CommandExists vim) { 'vim' }
elseif (Test-CommandExists vi) { 'vi' }
elseif (Test-CommandExists code) { 'code' }
elseif (Test-CommandExists notepad++) { 'notepad++' }
elseif (Test-CommandExists sublime_text) { 'sublime_text' }
else { 'notepad' }

$global:canConnectToGitHub = $null -ne (ping github.com -n 1 -w 1000 | Select-String "Reply from")

if (-not ((Get-Module -Name PSReadLine | Select-Object -ExpandProperty Version) -eq [Version] "2.3.6")) {
    Install-Module -Name PSReadLine -Scope CurrentUser -Force
}
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell ({0})$adminSuffix" -f $PSVersionTable.PSVersion.Major


#region PSReadLine Configuration
$PSReadLineOptions = @{
    ContinuationPrompt            = '  '
    EditMode                      = 'Windows'
    HistoryNoDuplicates           = $true
    HistorySearchCursorMovesToEnd = $true
    Colors                        = @{
        Command   = '#87CEEB'  # SkyBlue (pastel)
        Parameter = '#98FB98'  # PaleGreen (pastel)
        Operator  = '#FFB6C1'  # LightPink (pastel)
        Variable  = '#DDA0DD'  # Plum (pastel)
        String    = '#FFDAB9'  # PeachPuff (pastel)
        Number    = '#B0E0E6'  # PowderBlue (pastel)
        Type      = '#F0E68C'  # Khaki (pastel)
        Comment   = '#D3D3D3'  # LightGray (pastel)
        Keyword   = '#8367c7'  # Violet (pastel)
        Error     = '#FF6347'  # Tomato (keeping it close to red for visibility)
        Selection = '#e829f7'  # Black
    }
    PredictionViewStyle           = 'ListView'
    BellStyle                     = 'None'
}

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Set-PSReadLineOption -PredictionSource HistoryAndPlugin
}
else {
    Set-PSReadLineOption -PredictionSource History
}
Set-PSReadLineOption @PSReadLineOptions

Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadLineKeyHandler -Chord 'Ctrl+d' -Function DeleteChar
Set-PSReadLineKeyHandler -Chord 'Ctrl+w' -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord 'Alt+d' -Function DeleteWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+LeftArrow' -Function BackwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo
Set-PSReadLineKeyHandler -Chord 'Ctrl+f' -Function ForwardWord
Set-PSReadLineKeyHandler -Chord 'Enter' -Function ValidateAndAcceptLine

Set-PSReadLineOption -AddToHistoryHandler {
    param($line)
    $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
    $hasSensitive = $sensitive | Where-Object { $line -match $_ }
    return ($null -eq $hasSensitive)
}

Set-PSReadLineOption -MaximumHistoryCount 10000

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    $customCompletions = @{
        'git'  = @('status', 'add', 'commit', 'push', 'pull', 'clone', 'checkout')
        'npm'  = @('install', 'start', 'run', 'test', 'build')
        'deno' = @('run', 'compile', 'bundle', 'test', 'lint', 'fmt', 'cache', 'info', 'doc', 'upgrade')
    }
    
    $command = $commandAst.CommandElements[0].Value
    if ($customCompletions.ContainsKey($command)) {
        $customCompletions[$command] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
    }
}
Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock
#endregion PSReadLine Configuration

#region Zoxide Configuration
if (Get-Command zoxide -ErrorAction SilentlyContinue) {
    Invoke-Expression (& { (zoxide init --cmd cd powershell | Out-String) })
}
else {
    Write-Host "zoxide command not found. Attempting to install via winget..."
    try {
        winget install -e --id ajeetdsouza.zoxide
        Write-Host "zoxide installed successfully. Initializing..."
        Invoke-Expression (& { (zoxide init powershell | Out-String) })
    }
    catch {
        Write-Error "Failed to install zoxide. Error: $_"
    }
}

Set-Alias -Name z -Value __zoxide_z -Option AllScope -Scope Global -Force
Set-Alias -Name zi -Value __zoxide_zi -Option AllScope -Scope Global -Force
#endregion Zoxide Configuration
#endregion Configuration




#region Commands


#region Profile Managemenet
function Edit-Profile($editor = $EDITOR) {
    if ($editor -eq 'code') {
        code $PROFILE.CurrentUserAllHosts
    }
    else {
        & $editor $($PROFILE.CurrentUserAllHosts)
    }
}

function ep { vim $PROFILE }

function Reload-Profile {
    & $PROFILE
}

# Check for Profile Updates
function Update-Profile {
    try {
        $url = "https://raw.githubusercontent.com/66Bunz/powershell-profile/main/Microsoft.PowerShell_profile.ps1"
        $oldhash = Get-FileHash $PROFILE
        Invoke-RestMethod $url -OutFile "$env:temp/Microsoft.PowerShell_profile.ps1"
        $newhash = Get-FileHash "$env:temp/Microsoft.PowerShell_profile.ps1"
        if ($newhash.Hash -ne $oldhash.Hash) {
            Copy-Item -Path "$env:temp/Microsoft.PowerShell_profile.ps1" -Destination $PROFILE -Force
            Write-Host "Profile has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
        else {
            Write-Host "Profile is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Unable to check for `$profile updates: $_"
    }
    finally {
        Remove-Item "$env:temp/Microsoft.PowerShell_profile.ps1" -ErrorAction SilentlyContinue
    }
}
#endregion Profile Managemenet




#region General Commands
Set-Alias -Name vim -Value $EDITOR

function .. { Set-Location .. }

Set-Alias c Clear-Host

Set-Alias cl Clear-Host

Remove-Item -Force Alias:cat

Set-Alias cat bat

Set-Alias sass-convert sass

function docs { 
    $docs = if (([Environment]::GetFolderPath("MyDocuments"))) { ([Environment]::GetFolderPath("MyDocuments")) } else { $HOME + "\Documents" }
    Set-Location -Path $docs
}

function export($name, $value) {
    set-item -force -path "env:$name" -value $value;
}

function ff($name) {
    Get-ChildItem -recurse -filter "*${name}*" -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Output "$($_.FullName)"
    }
}

function grep($regex, $dir) {
    if ( $dir ) {
        Get-ChildItem $dir | select-string $regex
        return
    }
    $input | select-string $regex
}

function head {
    param($Path, $n = 10)
    Get-Content $Path -Head $n
}

function home { Set-Location "D:\users\bunz\Documents" }

function la { Get-ChildItem -Path . -Force | Format-Table -AutoSize }

function mkcd { param($dir) mkdir $dir -Force; Set-Location $dir }

function nf { param($name) New-Item -ItemType "file" -Path . -Name $name }

function sed($file, $find, $replace) {
    (Get-Content $file).replace("$find", $replace) | Set-Content $file
}

function tail {
    param($Path, $n = 10, [switch]$f = $false)
    Get-Content $Path -Tail $n -Wait:$f
}

function touch($file) { "" | Out-File $file -Encoding ASCII }

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter $file | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

#endregion General Commands




#region Git Shortcuts
function gs { git status }

function ga { git add . }

function gc { param($m) git commit -m "$m" }

function gp { git push }

function g { __zoxide_z github }

function gcl { git clone "$args" }

function gcom {
    git add .
    git commit -m "$args"
}
function lazyg {
    git add .
    git commit -m "$args"
    git push
}
#endregion Git Shortcuts




#region Clipboard Utilities
function cpy { Set-Clipboard $args[0] }

function pst { Get-Clipboard }
#endregion Clipboard Utilities




#region System Utilities
# Set-Alias sudo admin

function admin {
    if ($args.Count -gt 0) {
        $argList = "& '$args'"
        Start-Process wt -Verb runAs -ArgumentList "pwsh.exe -NoExit -Command $argList"
    }
    else {
        Start-Process wt -Verb runAs
    }
}

function Clear-Cache {
    # add clear cache logic here
    Write-Host "Clearing cache..." -ForegroundColor Cyan

    # Clear Windows Prefetch
    Write-Host "Clearing Windows Prefetch..." -ForegroundColor Yellow
    Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue

    # Clear Windows Temp
    Write-Host "Clearing Windows Temp..." -ForegroundColor Yellow
    Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Clear User Temp
    Write-Host "Clearing User Temp..." -ForegroundColor Yellow
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue

    # Clear Internet Explorer Cache
    Write-Host "Clearing Internet Explorer Cache..." -ForegroundColor Yellow
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host "Cache clearing completed." -ForegroundColor Green
}

function df {
    Get-Volume
}

function flushdns {
    Clear-DnsClientCache
    Write-Host "DNS has been flushed"
}

function Get-PubIP { (Invoke-WebRequest http://ifconfig.me/ip).Content }

function k9 { Stop-Process -Name $args[0] }

function pgrep($name) {
    Get-Process $name
}

function pkill($name) {
    Get-Process $name -ErrorAction SilentlyContinue | Stop-Process
}

function reboot { shutdown /r /t 0 }

function sysinfo { Get-ComputerInfo }

function Update-PowerShell {
    try {
        Write-Host "Checking for PowerShell updates..." -ForegroundColor Cyan
        $updateNeeded = $false
        $currentVersion = $PSVersionTable.PSVersion.ToString()
        $gitHubApiUrl = "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
        $latestReleaseInfo = Invoke-RestMethod -Uri $gitHubApiUrl
        $latestVersion = $latestReleaseInfo.tag_name.Trim('v')
        if ($currentVersion -lt $latestVersion) {
            $updateNeeded = $true
        }

        if ($updateNeeded) {
            Write-Host "Updating PowerShell..." -ForegroundColor Yellow
            winget upgrade "Microsoft.PowerShell" --accept-source-agreements --accept-package-agreements
            Write-Host "PowerShell has been updated. Please restart your shell to reflect changes" -ForegroundColor Magenta
        }
        else {
            Write-Host "Your PowerShell is up to date." -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to update PowerShell. Error: $_"
    }
}

function uptime {
    try {
        # check powershell version
        if ($PSVersionTable.PSVersion.Major -eq 5) {
            $lastBoot = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot)
        }
        else {
            $lastBootStr = net statistics workstation | Select-String "dal" | ForEach-Object { $_.ToString().Replace('Statistiche dal ', '') }
            $bootTime = [System.DateTime]::ParseExact($lastBootStr, "dd/MM/yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        
            # $lastBoot2 = (Get-WmiObject win32_operatingsystem).LastBootUpTime
            # $bootTime2 = [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBoot2)
        }

        # Format the start time
        $formattedBootTime = $bootTime.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        # $formattedBootTime2 = $bootTime2.ToString("dddd, MMMM dd, yyyy HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
        Write-Host "System started on: $formattedBootTime" -ForegroundColor DarkGray
        # Write-Host "System started on: $formattedBootTime2" -ForegroundColor DarkGray

        # calculate uptime
        $uptime = (Get-Date) - $bootTime

        # Uptime in days, hours, minutes, and seconds
        $days = $uptime.Days
        $hours = $uptime.Hours
        $minutes = $uptime.Minutes
        $seconds = $uptime.Seconds

        # Uptime output
        Write-Host ("Uptime: {0} days, {1} hours, {2} minutes, {3} seconds" -f $days, $hours, $minutes, $seconds) -ForegroundColor Blue

    }
    catch {
        Write-Error "An error occurred while retrieving system uptime."
    }
}

function which($name) {
    Get-Command $name | Select-Object -ExpandProperty Definition
}
#endregion System Utilities



#region Python
function py-env {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("create", "activate", "deactivate", "delete")]
        [string]$Command
    )

    switch ($Command) {
        "create" {
            Write-Host "Creating Python virtual environment..." -ForegroundColor Yellow
            python -m venv .venv
            Write-Host "Virtual environment created successfully!" -ForegroundColor Green
        }
        "activate" {
            if (Test-Path ".\.venv\Scripts\Activate") {
                Write-Host "Activating Python virtual environment..." -ForegroundColor Green
                & .\.venv\Scripts\Activate
            }
            else {
                Write-Host "Error: Virtual environment not found. Run 'py-env create' first." -ForegroundColor Red
            }
        }
        "deactivate" {
            Write-Host "Deactivating Python virtual environment..." -ForegroundColor Red
            deactivate
        }
        "delete" {
            if (Test-Path ".\.venv") {
                Write-Host "Deleting Python virtual environment..." -ForegroundColor Yellow
                Remove-Item -Recurse -Force .\.venv
                Write-Host "Virtual environment deleted successfully!" -ForegroundColor Green
            }
            else {
                Write-Host "No virtual environment found to delete." -ForegroundColor Red
            }
        }
    }
}
#endregion Python



#region Other Utilities
Set-Alias ch Show-Help

Set-Alias t transparency

$ssh_private_key = "D:\users\bunz\Documents\Alessandro\Varie\ssh\bunz-laptop-private-ssh"
function botssh { ssh root@134.209.119.212 -i $ssh_private_key }

function cam { microsoft.windows.camera: }

function Nvim-Config { nvim "C:\Users\bunz\AppData\Local\nvim" }

function Show-Help {
    $helpText = @"
$($PSStyle.Foreground.Cyan)PowerShell Profile Help$($PSStyle.Reset)
$($PSStyle.Foreground.Yellow)=======================$($PSStyle.Reset)

Profile Management:
  $($PSStyle.Foreground.Green)Edit-Profile$($PSStyle.Reset) - Opens the current user's profile for editing using the configured editor.
  $($PSStyle.Foreground.Green)ep$($PSStyle.Reset) - Opens the profile for editing.
  $($PSStyle.Foreground.Green)Reload-Profile$($PSStyle.Reset) - Reloads the current user's PowerShell profile.
  $($PSStyle.Foreground.Green)Update-Profile$($PSStyle.Reset) - Checks for profile updates from a remote repository and updates if necessary.
  
General Commands:
  $($PSStyle.Foreground.Green)..$($PSStyle.Reset) - Changes to the parent directory.
  $($PSStyle.Foreground.Green)docs$($PSStyle.Reset) - Changes the current directory to the user's Documents folder.
  $($PSStyle.Foreground.Green)export$($PSStyle.Reset) <name> <value> - Sets an environment variable.
  $($PSStyle.Foreground.Green)ff$($PSStyle.Reset) <name> - Finds files recursively with the specified name.
  $($PSStyle.Foreground.Green)grep$($PSStyle.Reset) <regex> [dir] - Searches for a regex pattern in files within the specified directory or from the pipeline input.
  $($PSStyle.Foreground.Green)head$($PSStyle.Reset) <path> [n] - Displays the first n lines of a file (default 10).
  $($PSStyle.Foreground.Green)la$($PSStyle.Reset) - Lists all files in the current directory with detailed formatting.
  $($PSStyle.Foreground.Green)mkcd$($PSStyle.Reset) <dir> - Creates and changes to a new directory.
  $($PSStyle.Foreground.Green)nf$($PSStyle.Reset) <name> - Creates a new file with the specified name.
  $($PSStyle.Foreground.Green)sed$($PSStyle.Reset) <file> <find> <replace> - Replaces text in a file.
  $($PSStyle.Foreground.Green)tail$($PSStyle.Reset) <path> [n] - Displays the last n lines of a file (default 10).
  $($PSStyle.Foreground.Green)touch$($PSStyle.Reset) <file> - Creates a new empty file.
  $($PSStyle.Foreground.Green)unzip$($PSStyle.Reset) <file> - Extracts a zip file to the current directory.
  
Git Shortcuts:
  $($PSStyle.Foreground.Green)g$($PSStyle.Reset) - Changes to the GitHub directory.
  $($PSStyle.Foreground.Green)ga$($PSStyle.Reset) - Shortcut for 'git add .'.
  $($PSStyle.Foreground.Green)gc$($PSStyle.Reset) <message> - Shortcut for 'git commit -m'.
  $($PSStyle.Foreground.Green)gcom$($PSStyle.Reset) <message> - Adds all changes and commits with the specified message.
  $($PSStyle.Foreground.Green)gp$($PSStyle.Reset) - Shortcut for 'git push'.
  $($PSStyle.Foreground.Green)gs$($PSStyle.Reset) - Shortcut for 'git status'.
  $($PSStyle.Foreground.Green)lazyg$($PSStyle.Reset) <message> - Adds all changes, commits with the specified message, and pushes to the remote repository.

Clipboard Utilities:
  $($PSStyle.Foreground.Green)cpy$($PSStyle.Reset) <text> - Copies the specified text to the clipboard.
  $($PSStyle.Foreground.Green)pst$($PSStyle.Reset) - Retrieves text from the clipboard.

System Utilities:
  $($PSStyle.Foreground.Green)admin$($PSStyle.Reset) <command> - Runs the specified command with elevated rights or opens a new admin terminal window.
  $($PSStyle.Foreground.Green)Clear-Cache$($PSStyle.Reset) - Clears the Windows cache.
  $($PSStyle.Foreground.Green)df$($PSStyle.Reset) - Displays information about volumes.
  $($PSStyle.Foreground.Green)flushdns$($PSStyle.Reset) - Clears the DNS cache.
  $($PSStyle.Foreground.Green)Get-PubIP$($PSStyle.Reset) - Retrieves the public IP address of the machine.
  $($PSStyle.Foreground.Green)k9$($PSStyle.Reset) <name> - Kills a process by name.
  $($PSStyle.Foreground.Green)pgrep$($PSStyle.Reset) <name> - Lists processes by name.
  $($PSStyle.Foreground.Green)pkill$($PSStyle.Reset) <name> - Kills processes by name.
  $($PSStyle.Foreground.Green)reboot$($PSStyle.Reset) - Restarts the system.
  $($PSStyle.Foreground.Green)sysinfo$($PSStyle.Reset) - Displays detailed system information.
  $($PSStyle.Foreground.Green)Update-PowerShell$($PSStyle.Reset) - Checks for the latest PowerShell release and updates if a new version is available.
  $($PSStyle.Foreground.Green)uptime$($PSStyle.Reset) - Displays the system uptime.
  $($PSStyle.Foreground.Green)which$($PSStyle.Reset) <name> - Shows the path of the command.

Python Utilities:
    $($PSStyle.Foreground.Green)py-env$($PSStyle.Reset) <command> - Manages Python virtual environments.

Other Utilities:
  $($PSStyle.Foreground.Green)botssh$($PSStyle.Reset) - Connects to the DigitalOcean droplet via SSH.
  $($PSStyle.Foreground.Green)cam$($PSStyle.Reset) - Opens the camera.
  $($PSStyle.Foreground.Green)Nvim-Config$($PSStyle.Reset) - Opens the Neovim configuration directory.
  $($PSStyle.Foreground.Green)time$($PSStyle.Reset) - Measures the execution time of a command.
  $($PSStyle.Foreground.Green)transparency$($PSStyle.Reset) <name> [value] - Sets the transparency of an app window to a specified value (default 245).
  $($PSStyle.Foreground.Green)winutil$($PSStyle.Reset) - Runs the WinUtil script from Chris Titus Tech.

Use '$($PSStyle.Foreground.Magenta)Show-Help$($PSStyle.Reset)' to display this help message.
"@
    Write-Host $helpText
}

function time { $Command = "$args"; Measure-Command { Invoke-Expression $Command 2>&1 | out-default } | Select-Object TotalMilliseconds }

function transparency {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias("Name")]
        [string]$name,

        [Parameter(Position = 1)]
        [int]$Value = $null
    )

    process {
        if (-Not $value) {
            nircmd win trans ititle $name 245
        }
        elseif ($Value -is [int]) {
            nircmd win trans ititle $name $Value
        }
        else {
            Write-Host "Invalid transparency value (must be between 0-255): $Value"
            return
        }
        Write-Output "Transparency applied to $name"
    }
}

function winutil {
    Invoke-WebRequest -useb https://christitus.com/win | Invoke-Expression
}
#endregion Other Utilities



#endregion Commands

$profileDirectory = Split-Path -Path $PROFILE
$ompThemeFiles = Get-ChildItem -Path $profileDirectory -Filter "*.omp.json"

function Get-Theme {
    if (Test-Path -Path $PROFILE.CurrentUserAllHosts -PathType leaf) {
        $existingTheme = Get-Content -Path $PROFILE.CurrentUserAllHosts | Select-String -Pattern "oh-my-posh init pwsh --config"
        if ($null -ne $existingTheme) {
            Invoke-Expression $existingTheme
            return
        }
        else {
            if ($ompThemeFiles) {
                $firstThemeFile = $ompThemeFiles | Select-Object -First 1
                if ($firstThemeFile) {
                    oh-my-posh init pwsh --config $firstThemeFile.FullName | Invoke-Expression
                }
            }
            else {
                oh-my-posh init pwsh --config https://raw.githubusercontent.com/66Bunz/powershell-profile/main/bunz-theme.omp.json | Invoke-Expression
            }
        }
    }
    else {
        if ($ompThemeFiles) {
            $firstThemeFile = $ompThemeFiles | Select-Object -First 1
            if ($firstThemeFile) {
                oh-my-posh init pwsh --config $firstThemeFile.FullName | Invoke-Expression
            }
        }
        else {
            oh-my-posh init pwsh --config https://raw.githubusercontent.com/66Bunz/powershell-profile/main/bunz-theme.omp.json | Invoke-Expression
        }
    }
}

Get-Theme

Write-Host "$($PSStyle.Foreground.Yellow)Use 'Show-Help' to display help$($PSStyle.Reset)"
