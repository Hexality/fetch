function fetch([switch]$v, [switch]$NoClear) {
  if ($IsWindows -or $IsLinux) {
    $global:cfg = @{
      # Available colors: "Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "BrightBlack", "BrightRed", "BrightGreen", "BrightYellow", "BrightBlue", "BrightMagenta", "BrightCyan", "BrightWhite"
    
      # From RGB, just change $null to FromRgb("RRR, GGG, BBB"). Example: FronRgb("231,130,132")
    
      # To use default console colors (windows-compatible), just change $null to FromConsoleColor("Color"). Example: FronConsoleColor("DarkRed")
      ###> Console colors: "Black", "DarkRed", "DarkGreen", "DarkYellow", "DarkBlue", "DarkMagenta", "DarkCyan","DarkGray", "Gray", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"
    
      AccentColor   = $null # Default: $null (None)
      FolderColor   = $null # Default: $null (Red)
      TextColor1    = $null # Default: $null (White)
      TextColor2    = $null # Default: $null (Gray)
      SystemLogoBg  = $null # Default: $null (OS dependent)
      SystemLogoFg  = $null # Default: $null (OS dependent)

      #CustomLogo      = $null # Default: $null (OS dependent)
      # CustomLogo      = # It needs to be 15 lines tall!!!!
      # "┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━┫",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┃             ┃             ┃",
      # "┗━━━━━━━━━━━━━┻━━━━━━━━━━━━━┛"
    
      UseBoldLogo   = $False # Default: $False (Off)
      UseHostname   = $False # Default: $False (Will use username instead)
      RamUsageAlert = $False
    
      #CustomName      = "DesiredNameToDisplay" # Replaces UseHostname/Default username.
      FrontSpacing  = $null # Default: $null (4)
      CenterSpacing = $null # Default: $null (4)

      Line0         = ""
      Line1         = "Linehost"
      Line2         = ""
      Line3         = "OSName"
      Line4         = ""
      Line5         = "Uptime"
      Line6         = "Packages"
      Line7         = ""
      Line8         = "CPU"
      Line9         = "GPU"
      Line10        = "RAM"
      Line11        = ""
      Line12        = "GridLine1"
      Line13        = "GridLine2"
      Line14        = ""
    }

    function Get-InstalledSoftware {
      [CmdletBinding()]
      param (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        [Parameter()]
        [guid]$Guid
      )
      process {
        try {
          $scriptBlock = {
            $args[0].GetEnumerator() | ForEach-Object { New-Variable -Name $_.Key -Value $_.Value }
            $UninstallKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
            New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null
            $UninstallKeys += Get-ChildItem HKU: | Where-Object { 
              $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' 
            } | ForEach-Object {
              "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            }
            if (-not $UninstallKeys) { Write-Warning -Message 'No software registry keys found' }
            else {
              foreach ($UninstallKey in $UninstallKeys) {
                $friendlyNames = @{
                  'DisplayName'    = 'Name'
                  'DisplayVersion' = 'Version'
                }
                Write-Verbose -Message "Checking uninstall key [$($UninstallKey)]"
                if ($Name) { $WhereBlock = { $_.GetValue('DisplayName') -like "$Name*" } }
                elseif ($GUID) { $WhereBlock = { $_.PsChildName -eq $Guid.Guid } }
                else { $WhereBlock = { $_.GetValue('DisplayName') } }
                $SwKeys = Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object $WhereBlock
                if (-not $SwKeys) {
                  Write-Verbose -Message "No software keys in uninstall key $UninstallKey"
                }
                else {
                  foreach ($SwKey in $SwKeys) {
                    $output = @{ }
                    foreach ($ValName in $SwKey.GetValueNames()) {
                      if ($ValName -ne 'Version') {
                        $output.InstallLocation = ''
                        if ($ValName -eq 'InstallLocation' -and 
                                            ($SwKey.GetValue($ValName)) -and 
                                            (@('C:', 'C:\Windows', 'C:\Windows\System32', 'C:\Windows\SysWOW64') -notcontains $SwKey.GetValue($ValName).TrimEnd('\'))) {
                          $output.InstallLocation = $SwKey.GetValue($ValName).TrimEnd('\')
                        }
                        [string]$ValData = $SwKey.GetValue($ValName)
                        if ($friendlyNames[$ValName]) {
                          $output[$friendlyNames[$ValName]] = $ValData.Trim() ## Some registry values have trailing spaces.
                        }
                        else {
                          $output[$ValName] = $ValData.Trim() ## Some registry values trailing spaces
                        }
                      }
                    }
                    $output.GUID = ''
                    if ($SwKey.PSChildName -match '\b[A-F0-9]{8}(?:-[A-F0-9]{4}){3}-[A-F0-9]{12}\b') {
                      $output.GUID = $SwKey.PSChildName
                    }
                    New-Object -TypeName PSObject -Prop $output
                  }
                }
              }
            }
          }

          if ($ComputerName -eq $env:COMPUTERNAME) {
            & $scriptBlock $PSBoundParameters
          }
          else {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock $scriptBlock -ArgumentList $PSBoundParameters
          }
        }
        catch {
          Write-Error -Message "Error: $($_.Exception.Message) - Line Number: $($_.InvocationInfo.ScriptLineNumber)"
        }
      }
    }

    function Get-LinuxPackages {
      if (Get-Command flatpak -ErrorAction SilentlyContinue) {
        $flatpak = (flatpak list).count - 1 #idk if this will work well though
      }
      if (Get-Command yum -ErrorAction SilentlyContinue) {
        $yum = (yum list --installed).count - 1 #idk if this will work well though
      }
      if (Get-Command zypper -ErrorAction SilentlyContinue) {
        $zyp = (zypper --no-refresh packages -i).count - 2 # this one is most definitely wrong in matter of numbers.
      }
      if (Get-Command dpkg -ErrorAction SilentlyContinue) {
        $dpkg = (dpkg -l | grep -c '^ii')
      }
      $appimage = (ls -R $HOME | grep -G '.appimage$').count

      $result = "$($flatpak + $yum + $zyp + $dpkg + $appimage)"
      $info = "($(if($flatpak) { "flatpak: $flatpak,"}; if($yum) { "yum/dnf: $yum,"}; if($zyp) { "zypper: $zyp,"}; if($dpkg) { "dpkg: $dpkg,"}; if($appimage) { "appimage: $appimage"}))"
      return [array]($result, $info)
    }
  
    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving username/hostname...";
        $PSStyle.Reset;
      ) -join ''
    }
    $Linehost = @(
      $PSStyle.Bold
      '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; ($cfg.CustomName) ?? ($cfg.UseHostname ? ([System.Net.Dns]::GetHostName()) : ($env:USER)); 
      $PSStyle.BoldOff
      '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; " at "; 
      $PSStyle.Bold
      '$PSStyle.Foreground.' + (($cfg.FolderColor) ?? ("FromConsoleColor('Red')")) | Invoke-Expression; if ((Resolve-Path .) -match $env:HOME) { (Resolve-Path .).Path.Replace($HOME, "~") } else { (Resolve-Path .).Path }
      $PSStyle.BoldOff
      $PSStyle.Reset;
    ) -join ''

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving kernel version..."
        $PSStyle.Reset
      ) -join ''
    }
    $KernelVersion = if ($isWindows) {
 (Get-Item C:\Windows\System32\ntoskrnl.exe).VersionInfo.ProductVersionRaw 
    }
    elseif ($isLinux) { uname -r }

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving OS name..."
        $PSStyle.Reset
      ) -join ''
    }
    $OSName = @(
      @(
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "OS: "
        $PSStyle.BoldOff
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; if ($isLinux) {
        (Get-Content /etc/os-release | ConvertFrom-StringData).Name.Trim('"')
        }
        elseif ($IsWindows) {
        ((wmic os get Caption)[2]).Substring('10', '14')
        }
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')")) | Invoke-Expression; " ($($isWindows ? ('') : ('Running on')) $KernelVersion)"
        $PSStyle.Reset
      ) -join ''
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving uptime..."
        $PSStyle.Reset
      ) -join ''
    }
    $Uptime = $(
      $Uptime = Get-Uptime | Select-Object Days, Hours, Minutes, Seconds
      @(
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "Uptime: "; $PSStyle.BoldOff
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $Uptime.Days
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')" )) | Invoke-Expression; ; " days, "
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $Uptime.Hours
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')" )) | Invoke-Expression; ; " hours, "
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $Uptime.Minutes
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')" )) | Invoke-Expression; ; " minutes, "
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $Uptime.Seconds
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')" )) | Invoke-Expression; ; " seconds. "
        #"$($Uptime.Days) Days, $($Uptime.Hours) Hours, $($Uptime.Minutes) Minutes, $($Uptime.Seconds) Seconds"
      ) -join ''
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving installed packages..."
        $PSStyle.Reset
      ) -join ''
    }
    $Packages = @(
      @(
      
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "Packages: "; $PSStyle.BoldOff
        $pkg = if ($isLinux) { 
          Get-LinuxPackages 
        }
        elseif ($IsWindows) {
        ((Get-InstalledSoftware -ErrorAction SilentlyContinue).Name).Count, "System$(if((Get-Command scoop -erroraction silentlycontinue).source ){" and Scoop"}))"
        }
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $pkg[0];
        " ";
        '$PSStyle.Foreground.' + (($cfg.TextColor2) ?? ("FromConsoleColor('DarkGray')")) | Invoke-Expression; $pkg[1];
        $PSStyle.Reset
      ) -join ''
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving CPU name..."
        $PSStyle.Reset
      ) -join ''
    }
    $CPU = @(
      if ($IsLinux) {
        $cpuinf = (lscpu -J | ConvertFrom-Json).lscpu
        $cpucore = ($cpuinf | Where-Object field -match "per socket").data
        $tmulti = ($cpuinf | Where-Object field -match "per core").data
      }
      $cpuname = if ($IsLinux) { ($cpuinf | Where-Object field -match "Model name").data } elseif ($IsWindows) { (Get-WmiObject -Class Win32_Processor -ComputerName.).Name }
      @(
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "CPU: "; $PSStyle.BoldOff
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $cpuname;
        $isLinux ? $('$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; " ("; '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; "$([int]$cpucore)C, $([int]$cpucore*[int]$tmulti)T"; '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; ")") : $null
        $PSStyle.Reset;
      ) -join ''
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving GPU name..."
        $PSStyle.Reset
      ) -join ''
    }
    $GPU = @(
      @(
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "GPU: "; $PSStyle.BoldOff
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; if ($IsLinux) { (lspci | grep VGA | cut -d ":" -f3).Substring(1) } elseif ($isWindows) { (Get-WmiObject win32_VideoController).VideoProcessor } 
        $PSStyle.Reset
      ) -join ''  
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Retrieving RAM usage..."
        $PSStyle.Reset
      ) -join ''
    }
    $RAM = @(
      if ($isWindows) { 
        $memd = (wmic computersystem get totalphysicalmemory)[2]
        $freem = (wmic OS get FreePhysicalMemory)[2]
        $usedm = [Math]::Round((($memd / 1024 / 1024 / 1024) - ($freem / 1024 / 1024)), 2)
        $totm = [math]::Round(((($memd / 1024) / 1024) / 1024), 2)
        $symbol = "GB"
      }
      elseif ($isLinux) {
        $memd = (awk '{ if (/MemAvailable:/) {mem_available=$2}; if (/MemTotal:/) {mem_total=$2}; if (mem_available && mem_total){ print int(mem_available/1024)","int(mem_total/1024); exit }}' /proc/meminfo).Split(",")
        $usedm = [Math]::Round((($memd[1] - $memd[0]) / 1024), 2)
        $totm = [math]::Round(($memd[1] / 1024), 2)
        $symbol = "GiB"
      }
      @(
        $PSStyle.Bold
        '$PSStyle.Foreground.' + (($cfg.AccentColor) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; "RAM: "; $PSStyle.BoldOff
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; "Used "; 
        if ($usedm -gt $totm * .6 -and $usedm -lt $totm * .8) {
          $cfg.RamUsageAlert ? $('$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression) : ($PSStyle.Foreground.FromConsoleColor("Yellow"))
        }
        elseif ($usedm -gt $totm * .8) {
          $cfg.RamUsageAlert ? $('$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression) : ($PSStyle.Foreground.FromConsoleColor("Red"))
        }
        else {
          '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression        
        }
        "$($usedm)"                                        
        '$PSStyle.Foreground.' + (($cfg.TextColor1) ?? ("FromConsoleColor('White')")) | Invoke-Expression; "$($symbol) out of $($totm;$symbol)"
        $PSStyle.Reset
      ) -join ''
    )

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Generating color grid..."
        $PSStyle.Reset
      ) -join ''
    }
    [Array]$GridColors = @("Black", "DarkRed", "DarkGreen", "DarkYellow", "DarkBlue", "DarkMagenta", "DarkCyan", "Gray", "DarkGray", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White")
    $GridCounter = 0
    $Counter = 0
    [Array]$ColorGrid = $GridColors.ForEach({
        @(
          $PSStyle.Foreground.FromConsoleColor($_)
          $PSStyle.Background.FromConsoleColor($_)
          "██"
          $PSStyle.Reset
          $Counter++
          if ($Counter -eq 4) {
            $GridCounter++
          }
        ) -join ''
      })

    if ($v) {
      @($PSStyle.Background.FromConsoleColor("DarkYellow"); $PSStyle.Foreground.FromConsoleColor("Black"); 
        "Generating..."
        $PSStyle.Reset
      ) -join ''
    }

    if (!$NoClear) {
      Clear-Host
    }

    if ($cfg.CustomLogo) {
      $SystemLogo += $cfg.CustomLogo.ForEach({
          @(
            " " * (($cfg.FrontSpacing) ?? 4); 
            $cfg.UseBoldLogo ? ($PSStyle.Bold) : $null
            '$PSStyle.Background.' + (($cfg.SystemLogoBg) ?? ("FromConsoleColor('Black')")) | Invoke-Expression; '$PSStyle.Foreground.' + (($cfg.SystemLogoFg) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $_; 
            $cfg.UseBoldLogo ? ($PSStyle.BoldOff) : $null
            $PSStyle.Reset
          ) -join '';
        })
    }
    else {
      if ($isWindows) {
        [array]$SystemLogo += @(
          "┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┣━━━━━━━━━━━━━╋━━━━━━━━━━━━━┫",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┃             ┃             ┃",
          "┗━━━━━━━━━━━━━┻━━━━━━━━━━━━━┛"
        ).ForEach({
            @(
              " " * (($cfg.FrontSpacing) ?? 4); 
              $cfg.UseBoldLogo ? ($PSStyle.Bold) : $null
              '$PSStyle.Background.' + (($cfg.SystemLogoBg) ?? ("FromConsoleColor('Blue')")) | Invoke-Expression; '$PSStyle.Foreground.' + (($cfg.SystemLogoFg) ?? ("FromConsoleColor('White')")) | Invoke-Expression; $_; 
              $cfg.UseBoldLogo ? ($PSStyle.BoldOff) : $null
              $PSStyle.Reset
            ) -join '';
          })
      }
      elseif ($isLinux) {
        if ((Get-Content /etc/os-release | ConvertFrom-StringData).Name.Trim('"') -match "Tumbleweed") {
          [array]$SystemLogo += @(
            "                              ",
            "                              ",
            "                              ",
            "                              ",
            "                              ",
            "   ⠀⠀⡠⡐⠄⠆⢔⠠⡀⠀⠀⠀⠀⠀⡀⠔⠐⠈⠂⠃⠢⢂⢀⠀   ",
            "   ⠀⠎⠀⠀⠀⠀⠀⠈⠌⠪⡀⠀⡐⠌⠀⠀⠀⠀⠀⠀⠀⠀⠑⠄   ",
            "   ⠪⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢕   ",
            "   ⠈⡢⠀⠀⠀⠀⠀⢀⠰⡨⠂⠀⢐⠔⠔⠀⠀⠀⠀⠀⠀⢀⢔⠁   ",
            "   ⠀⠈⠘⠰⠐⠔⠌⠊⠈⠀⠀⠀⠀⠁⠁⠃⠆⢄⢄⢄⠆⠒⠀⠀   ",
            "                              ",
            "                              ",
            "                              ",
            "                              ",
            "                              "
          ).ForEach({
              @(
                " " * (($cfg.FrontSpacing) ?? 4); 
                $cfg.UseBoldLogo ? ($PSStyle.Bold) : $null
                '$PSStyle.Background.' + (($cfg.SystemLogoBg) ?? ("FromConsoleColor('Green')")) | Invoke-Expression; '$PSStyle.Foreground.' + (($cfg.SystemLogoFg) ?? ("FromConsoleColor('Black')")) | Invoke-Expression; $_; 
                $cfg.UseBoldLogo ? ($PSStyle.BoldOff) : $null
                $PSStyle.Reset
              ) -join '';
            })
        }
      }
    }

    $GridLine1 = $ColorGrid[8..15] -join ''
    $GridLine2 = $ColorGrid[0..7] -join ''

    [Array]$DisplayInfo = "`n"
    $DisplayInfo += for ($i = 0; $i -lt $SystemLogo.Count; $i++) {
      $SystemLogo[$i] + "    " + $(
        switch ($i) { 
          0 { $cfg.Line0  ? ((Get-Variable $cfg.Line0 ).Value) : $null }
          1 { $cfg.Line1  ? ((Get-Variable $cfg.Line1 ).Value) : $null }
          2 { $cfg.Line2  ? ((Get-Variable $cfg.Line2 ).Value) : $null }
          3 { $cfg.Line3  ? ((Get-Variable $cfg.Line3 ).Value) : $null }
          4 { $cfg.Line4  ? ((Get-Variable $cfg.Line4 ).Value) : $null }
          5 { $cfg.Line5  ? ((Get-Variable $cfg.Line5 ).Value) : $null }
          6 { $cfg.Line6  ? ((Get-Variable $cfg.Line6 ).Value) : $null }
          7 { $cfg.Line7  ? ((Get-Variable $cfg.Line7 ).Value) : $null }
          8 { $cfg.Line8  ? ((Get-Variable $cfg.Line8 ).Value) : $null };
          9 { $cfg.Line9  ? ((Get-Variable $cfg.Line9 ).Value) : $null };
          10 { $cfg.Line10 ? ((Get-Variable $cfg.Line10).Value) : $null };
          11 { $cfg.Line11 ? ((Get-Variable $cfg.Line11).Value) : $null }
          12 { $cfg.Line12 ? ((Get-Variable $cfg.Line12).Value) : $null };
          13 { $cfg.Line13 ? ((Get-Variable $cfg.Line13).Value) : $null };
          14 { $cfg.Line14 ? ((Get-Variable $cfg.Line14).Value) : $null }
        }
      )
    }

    $DisplayInfo
    "`n"
  }
  else {
    Write-Error "Your operating system isn't supported by this script."
  }
}
