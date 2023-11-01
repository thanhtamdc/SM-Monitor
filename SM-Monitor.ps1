# basedOn: https://discord.com/channels/623195163510046732/691261331382337586/1142174063293370498
#and also: https://github.com/PlainLazy/crypto/blob/main/sm_watcher.ps1
# With Thanks To: == S A K K I == Stizerg == PlainLazy == Shanyaa
#For the various contributions in making this script awesome
#
# get grpcurl here: https://github.com/fullstorydev/grpcurl/releases
$host.ui.RawUI.WindowTitle = "SM-Monitor"
function main {
    Clear-Host
    Write-Host "Loading ..." -NoNewline -ForegroundColor Cyan
    $grpcurl = "grpcurl.exe"
	$GenesisDate = [datetime]"07-14-2023 15:00"
    ############## Start Edit  ##############
    #Set your Email for notifications
    $emailEnable = "True" #True to enable email notification, False to disable
    $myEmail = ""
    
    $list = @(
        @{ info = "N225-1"; host = "192.168.1.225";  port = 9092; port2 = 9093; }
        @{ info = "N225-2"; host = "192.168.1.225";  port = 9292; port2 = 9293; }
	
    )
    ############## Finish Edit ##############

    $gitVersion = Invoke-RestMethod -Method 'GET' -uri "https://api.github.com/repos/spacemeshos/go-spacemesh/releases/latest" 2>$null
    if ($null -ne $gitVersion) {
        $gitVersion = $gitVersion.tag_name
    }

    # Colors: Black, Blue, Cyan, DarkBlue, DarkCyan, DarkGray, DarkGreen, DarkMagenta, DarkRed, DarkYellow, Gray, Green, Magenta, Red, White, Yellow
    $columnRules = @(
        @{ Column = "Info"; Value = "*"; ForegroundColor = "Cyan"; BackgroundColor = "Black" },
        @{ Column = "SID"; Value = "*"; ForegroundColor = "Yellow"; BackgroundColor = "Black" },
        @{ Column = "Host"; Value = "*"; ForegroundColor = "White"; BackgroundColor = "Black" },
        @{ Column = "Port"; ForegroundColor = "White"; BackgroundColor = "Black" },
        @{ Column = "PRs"; Value = "*"; ForegroundColor = "DarkCyan"; BackgroundColor = "Black" },
        @{ Column = "PRs"; Value = "0"; ForegroundColor = "DarkGray"; BackgroundColor = "Black" },
        @{ Column = "SU"; Value = "*"; ForegroundColor = "Yellow"; BackgroundColor = "Black" },
        @{ Column = "SzTiB"; Value = "*"; ForegroundColor = "White"; BackgroundColor = "Black" },
        @{ Column = "Synced"; Value = "True"; ForegroundColor = "Green"; BackgroundColor = "Black" },
        @{ Column = "Synced"; Value = "False"; ForegroundColor = "DarkRed"; BackgroundColor = "Black" },
        @{ Column = "Synced"; Value = "Offline"; ForegroundColor = "DarkGray"; BackgroundColor = "Black" },
        @{ Column = "Layer Top Verified"; Value = "*"; ForegroundColor = "White"; BackgroundColor = "Black" },
        @{ Column = "Version"; Value = "*"; ForegroundColor = "Red"; BackgroundColor = "Black" },
        @{ Column = "Version"; Value = $gitVersion; ForegroundColor = "Green"; BackgroundColor = "Black" },
        @{ Column = "Version"; Value = "Offline"; ForegroundColor = "DarkGray"; BackgroundColor = "Black" },
        @{ Column = "Smeshing"; Value = "*"; ForegroundColor = "Yellow"; BackgroundColor = "Black" },
        @{ Column = "Smeshing"; Value = "True"; ForegroundColor = "Green"; BackgroundColor = "Black" },
        @{ Column = "Smeshing"; Value = "False"; ForegroundColor = "DarkRed"; BackgroundColor = "Black" },
        @{ Column = "Smeshing"; Value = "Offline"; ForegroundColor = "DarkGray"; BackgroundColor = "Black" },
	@{ Column = "Rewards"; Value = "*"; ForegroundColor = "DarkCyan"; BackgroundColor = "Black" },
	@{ Column = "Rewards"; Value = "0"; ForegroundColor = "DarkGray"; BackgroundColor = "Black" },
	@{ Column = "FProof"; Value = "*"; ForegroundColor = "DarkRed"; BackgroundColor = "Black" },
        @{ Column = "FProof"; Value = "True"; ForegroundColor = "Green"; BackgroundColor = "Black" },
	@{ Column = "FProof"; Value = "Idle"; ForegroundColor = "White"; BackgroundColor = "Black" },
	@{ Column = "Registered"; Value = "*"; ForegroundColor = "DarkRed"; BackgroundColor = "Black" },
	@{ Column = "Registered"; Value = "Idle"; ForegroundColor = "White"; BackgroundColor = "Black" },
        @{ Column = "Registered"; Value = "True"; ForegroundColor = "Green"; BackgroundColor = "Black" }
    )
		
    if ($null -eq $gitVersion) {
        foreach ($rule in $ColumnRules) {
            if (($rule.Column -eq "Version") -and ($rule.Value -eq "*")) {
                $rule.ForegroundColor = "White"
                break
            }
        }
    }
    
    while (1) {

        $object = @()
        $resultsNodeHighestATX = $null
        $epoch = $null
	$totalsu = 0
	$totalrw = 0
	$Body = $null
	$offlineNodes = $null

        foreach ($node in $list) {
            Write-Host  " $($node.info)" -NoNewline -ForegroundColor Cyan

            if ($null -eq $resultsNodeHighestATX) {
                $resultsNodeHighestATX = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 5 $($node.host):$($node.port) spacemesh.v1.ActivationService.Highest")) | ConvertFrom-Json).atx 2>$null
            }
            if ($null -eq $epoch) {
                $epoch = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port) spacemesh.v1.MeshService.CurrentEpoch")) | ConvertFrom-Json).epochnum 2>$null
            }
                
            $status = $null
            $status = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port) spacemesh.v1.NodeService.Status")) | ConvertFrom-Json).status  2>$null
            Write-Host -NoNewline "." -ForegroundColor Cyan

            if ($null -ne $status) {
                $node.online = "True"
                if ($status.isSynced) {
                    $node.synced = "True"
                }
                else { $node.synced = "False" }
                $node.connectedPeers = $status.connectedPeers
                $node.syncedLayer = $status.syncedLayer.number
                $node.topLayer = $status.topLayer.number
                $node.verifiedLayer = $status.verifiedLayer.number
            }
            else {
                $node.online = ""
                $node.smeshing = "Offline"
                $node.synced = "Offline"
            }

            if ($node.online) {
                $version = $null
                $version = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port) spacemesh.v1.NodeService.Version")) | ConvertFrom-Json).versionString.value  2>$null
                Write-Host -NoNewline "." -ForegroundColor Cyan
                if ($null -ne $version) {
                    $node.version = $version
                }

                #Uncomment next line if your Smapp using standard configuration -- 1 of 2
                #if (($node.host -eq "localhost") -Or ($node.host -ne "localhost" -And $node.port2 -ne 9093)){ 
                $smeshing = $null
                $smeshing = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port2) spacemesh.v1.SmesherService.IsSmeshing")) | ConvertFrom-Json)	2>$null

                if ($null -ne $smeshing)
                { $node.smeshing = "True" } else { $node.smeshing = "False" }

                $state = $null
                $state = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port2) spacemesh.v1.SmesherService.PostSetupStatus")) | ConvertFrom-Json).status 2>$null
                Write-Host -NoNewline "." -ForegroundColor Cyan
        
                if ($null -ne $state) {
                    $node.numUnits = $state.opts.numUnits
                    
                    if ($state.state -eq "STATE_IN_PROGRESS") {
                        $percent = [math]::round(($state.numLabelsWritten / 1024 / 1024 / 1024 * 16) / ($state.opts.numUnits * 64) * 100, 1)
                        $node.smeshing = "$($percent)%"
                    }
                }
		$CurrentDate = Get-Date
		$NextEpoch = $GenesisDate.AddDays(($epoch.number + 1) * 14)
		$NextProofingWindowStarts = $NextEpoch.AddDays(-4.5)
		$NextSubmitATX = $NextEpoch.AddDays(-4-(1/24))
		$rewards = $null
		$findproof = $null
		$reg = $null
		$eventstream = (Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port2) spacemesh.v1.AdminService.EventsStream")) 2>$null
		echo '[' > json.txt
		echo $eventstream >> json.txt
		echo ']' >> json.txt
		$FilePath = "json.txt"
		(Get-Content -Raw -Path $FilePath) -replace '\r\n','' | Set-Content -Path $FilePath
		(Get-Content -Raw -Path $FilePath) -replace '}{','},{' | Set-Content -Path $FilePath
		$jsonObject = Get-Content -Path $FilePath | Out-String | ConvertFrom-JSON
                $rewards = (($jsonObject.eligibilities | Where-Object {$_.epoch -eq $epoch.number}).eligibilities | measure).Count
		$findproof = ($jsonObject.poetWaitRound)
		$reg = ($jsonObject.poetWaitProof)
		if ($null -ne $rewards){$node.rewards = $rewards}
		if (($CurrentDate -gt $NextProofingWindowStarts) -and ($CurrentDate -lt $NextEpoch)){
		if ($findproof.current -eq $epoch.number) {$node.findproof = "True"} else { $node.findproof = "False" }
		if ($reg.publish -eq $epoch.number + 1) {$node.reg = "True"} else { $node.reg = "False" }
			}
			else {
				$node.findproof = "Idle"
				$node.reg = "Idle"
			}
				        
                $publicKey = $null
                $publicKey = ((Invoke-Expression ("$($grpcurl) --plaintext -max-time 3 $($node.host):$($node.port2) spacemesh.v1.SmesherService.SmesherID")) | ConvertFrom-Json).publicKey 2>$null
        
        
                #Convert SmesherID to HEX
                if ($null -ne $publicKey) {
                    $publicKey2 = (B64_to_Hex -id2convert $publicKey)
                    #Extract last 5 digits from SmesherID
                    $node.key = $publicKey2.substring($publicKey2.length - 5, 5)
                }
                #Uncomment next line if your Smapp using standard configuration -- 2 of 2
                #}  
            }
                       
            $o = [PSCustomObject]@{
                Info      = $node.info
                SID = $node.key
                Host      = $node.host
                Port      = $node.port
                PRs     = $node.connectedPeers
                SU        = $node.numUnits
                SzTiB   = [math]::round(($node.numUnits * 64 /1024),2)
                Synced    = $node.synced
                Layer     = $node.syncedLayer
                Top       = $node.topLayer
                Verified  = $node.verifiedLayer
                Version   = $node.version
                Smeshing  = $node.smeshing
		Rewards   = $node.rewards
		FProof     = $node.findproof
		Registered       = $node.reg
            } 
            $object += $o
	    $totalsu = $totalsu + $node.numUnits
	    $totalrw = $totalrw + $node.rewards
        }

        Clear-Host
	if ($NextProofingWindowStarts -lt $CurrentDate){$NextProofingWindowStarts = $NextProofingWindowStarts.AddDays(14)}
	if ($NextSubmitATX -lt $CurrentDate){$NextSubmitATX = $NextSubmitATX.AddDays(14)}
	$object | Select-Object Info, SID, Port, PRs, SU, SzTiB, Synced, Layer, Top, Verified, Version, Smeshing, Rewards, FProof, Registered | ColorizeMyObject -ColumnRules $columnRules
        #Write-Host `n
        Write-Host "----------------------------------------- Info: --------------------------------------" -ForegroundColor Yellow
        Write-Host "         Current Epoch: " -ForegroundColor Cyan -nonewline; Write-Host $epoch.number -ForegroundColor Green
        if ($null -ne $resultsNodeHighestATX) {
        Write-Host "           Highest ATX: " -ForegroundColor Cyan -nonewline; Write-Host (B64_to_Hex -id2convert $resultsNodeHighestATX.id.id) -ForegroundColor Green
        }
        Write-Host "         ATX Base64_ID: " -ForegroundColor Cyan -nonewline; Write-Host $resultsNodeHighestATX.id.id -ForegroundColor Green
	Write-Host "         Total SizeTiB: " -ForegroundColor Cyan -nonewline; Write-Host ([math]::round(($totalsu * 64 /1024),2)) -ForegroundColor Green -nonewline; Write-Host " TiB"
	Write-Host "              Total SU: " -ForegroundColor Cyan -nonewline; Write-Host ($totalsu) -ForegroundColor Green -nonewline; Write-Host " SUs"
	Write-Host "         Total Rewards: " -ForegroundColor Cyan -nonewline; Write-Host ($totalrw) -ForegroundColor Green -nonewline; Write-Host " Layers"
	Write-Host "  Next Proofing Window: " -ForegroundColor Cyan -nonewline; Write-Host $NextProofingWindowStarts -ForegroundColor Green;
	Write-Host "Next ATX Submit Window: " -ForegroundColor Cyan -nonewline; Write-Host $NextSubmitATX -ForegroundColor Green;
        #Write-Host "        Layer: " -ForegroundColor Cyan -nonewline; Write-Host $resultsNodeHighestATX.layer.number -ForegroundColor Green
        #Write-Host "     NumUnits: " -ForegroundColor Cyan -nonewline; Write-Host $resultsNodeHighestATX.numUnits -ForegroundColor Green
        #Write-Host "      PrevATX: " -ForegroundColor Cyan -nonewline; Write-Host $resultsNodeHighestATX.prevAtx.id -ForegroundColor Green
        #Write-Host "    SmesherID: " -ForegroundColor Cyan -nonewline; Write-Host $resultsNodeHighestATX.smesherId.id -ForegroundColor Green
        Write-Host "--------------------------------------------------------------------------------------" -ForegroundColor Yellow
        Write-Host `n
        $newline = "`r`n"
    
        #Version Check
        if ($null -ne $gitVersion) {
            $currentVersion = $gitVersion -replace "[^.0-9]"
            Write-Host "Github Go-Spacemesh version: $($gitVersion)" -ForegroundColor Green
            foreach ($node in ($object | Where-Object { $_.synced -notmatch "Offline" })) {
                $node.version = $node.version -replace "[^.0-9]"
                if ([version]$node.version -lt [version]$currentVersion) {
                    Write-Host "Info:" -ForegroundColor White -nonewline; Write-Host " --> Some of your nodes are Outdated!" -ForegroundColor DarkYellow
                    break
                }
            }
        }
        if ($object.synced -match "Offline") {
            Write-Host "Info:" -ForegroundColor White -nonewline; Write-Host " --> Some of your nodes are Offline!" -ForegroundColor DarkYellow
            if ($emailEnable -eq "True"){
            Write-Host "Email sent..." -ForegroundColor DarkYellow
            [array]$offlineNodes += $object | Where-Object { $_.synced -match "Offline" }
            $From = ""
            $To = $myEmail
            $Subject = "Node offline alert!"
            $Body = "Warning, some nodes are offline!"
            foreach ($item in $offlineNodes) {
                $Body = $body + $newLine + $item.Info + " " + $item.Host + " " + $item.Smeshing 
            }
    
            # Define the SMTP server details
            $SMTPServer = ""
            $SMTPPort = 25
            $SMTPUsername = ""
            $SMTPPassword = ""

            # Create a new email object
            $Email = New-Object System.Net.Mail.MailMessage
            $Email.From = $From
            $Email.To.Add($To)
            $Email.Subject = $Subject
            $Email.Body = $Body
            # Uncomment below to send HTML formatted email
            #$Email.IsBodyHTML = $true

            # Create an SMTP client object and send the email
            $SMTPClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
            $SMTPClient.EnableSsl = $false
            $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($SMTPUsername, $SMTPPassword)
            $SMTPClient.Send($Email)
            
        }
    }

        
        
        $currentDate = Get-Date -Format HH:mm:ss
        #Refresh
        Write-Host `n                
        Write-Host "Last refresh: " -ForegroundColor Yellow -nonewline; Write-Host "$currentDate" -ForegroundColor Green;

        #Loading
        $originalPosition = $host.UI.RawUI.CursorPosition
        for ($s = 0; $s -le 60; $s++) {
            Write-Host -NoNewline "." -ForegroundColor Cyan
            Start-Sleep 10
        }	
        $clearmsg = " " * ([System.Console]::WindowWidth - 1)  
        [Console]::SetCursorPosition($originalPosition.X, $originalPosition.Y)
        [System.Console]::Write($clearmsg) 
        [Console]::SetCursorPosition($originalPosition.X, $originalPosition.Y)
        Write-Host "Loading ..." -NoNewline -ForegroundColor Cyan
    }
}



function B64_to_Hex {
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$id2convert
    )
    [System.BitConverter]::ToString([System.Convert]::FromBase64String($id2convert)).Replace("-", "")
}
function Hex_to_B64 {
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string]$id2convert
    )
    $NODE_ID_BYTES = for ($i = 0; $i -lt $id2convert.Length; $i += 2) { [Convert]::ToByte($id2convert.Substring($i, 2), 16) }
    [System.Convert]::ToBase64String($NODE_ID_BYTES)
}
function ColorizeMyObject {
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$ColumnRules
    )

    begin {
        $dataBuffer = @()
    }

    process {
        $dataBuffer += $InputObject
    }

    end {
        $headers = $dataBuffer[0].PSObject.Properties.Name

        $maxWidths = @{}
        foreach ($header in $headers) {
            $headerLength = "$header".Length
            $dataMaxLength = ($dataBuffer | ForEach-Object { "$($_.$header)".Length } | Measure-Object -Maximum).Maximum
            $maxWidths[$header] = [Math]::Max($headerLength, $dataMaxLength)
        }
    
        $headers | ForEach-Object { 
            $paddedHeader = $_.PadRight($maxWidths[$_])
            Write-Host $paddedHeader -NoNewline; 
            Write-Host "  " -NoNewline 
        }
        Write-Host ""

        $headers | ForEach-Object {
            $dashes = '-' * $maxWidths[$_]
            Write-Host $dashes -NoNewline
            Write-Host "  " -NoNewline
        }
        Write-Host ""
    
        foreach ($row in $dataBuffer) {
            foreach ($header in $headers) {
                $propertyValue = "$($row.$header)"
                $foregroundColor = $null
                $backgroundColor = $null

                foreach ($rule in $ColumnRules) {
                    if ($header -eq $rule.Column) {
                        if ($propertyValue -like $rule.Value) {
                            $foregroundColor = $rule.ForegroundColor
                            if ($rule.BackgroundColor) {
                                $backgroundColor = $rule.BackgroundColor
                            }
                            #break
                        }
                    }
                }

                $paddedValue = $propertyValue.PadRight($maxWidths[$header])

                if ($foregroundColor -or $backgroundColor) {
                    if ($backgroundColor) {
                        Write-Host $paddedValue -NoNewline -ForegroundColor $foregroundColor -BackgroundColor $backgroundColor
                    }
                    else {
                        Write-Host $paddedValue -NoNewline -ForegroundColor $foregroundColor
                    }
                }
                else {
                    Write-Host $paddedValue -NoNewline
                }

                Write-Host "  " -NoNewline
            }
            Write-Host ""
        }
    }
}
main
