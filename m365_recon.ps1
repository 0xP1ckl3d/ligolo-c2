param (
    [Parameter(Mandatory = $true)]
    [string]$Domain
)

function Format-KeyValueSummary {
    param ([string]$Key, [string[]]$Values)
    Write-Host -ForegroundColor Cyan ("{0,-22}:" -f $Key) -NoNewline
    Write-Host " $($Values[0])"
    if ($Values.Count -gt 1) {
        $Values[1..($Values.Count - 1)] | ForEach-Object {
            Write-Host -ForegroundColor Cyan ("{0,-22}  {1}" -f '', $_)
        }
    }
}

Write-Host "[*] Checking normal MX records for $Domain" -ForegroundColor Cyan
$originalMX = @()
try {
    $originalMX = (Resolve-DnsName -Name $Domain -Type MX -ErrorAction Stop).NameExchange
    $originalMX | ForEach-Object { Write-Host "[+] MX: $_" -ForegroundColor Green }
} catch {
    $originalMX = @("[-] Unresolved")
    Write-Host "[-] Could not resolve MX for $Domain" -ForegroundColor Yellow
}

$SoapBody = @'
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:a="http://www.w3.org/2005/08/addressing"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request>
        <Domain>{0}</Domain>
      </Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>
'@ -f $Domain

$headers = @{
    "Content-Type" = "text/xml; charset=utf-8"
    "SOAPAction"   = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'
    "User-Agent"   = "AutodiscoverClient"
}

Write-Host "`n[*] Querying Microsoft for tenant-linked domains..." -ForegroundColor Cyan
try {
    $response = Invoke-WebRequest -Uri "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc" `
                                  -Method POST -Body $SoapBody -Headers $headers -UseBasicParsing -ErrorAction Stop

    $matchesAll = Select-String -InputObject $response.Content -Pattern '<Domain>([^<]+)</Domain>' -AllMatches
    $allDomains = $matchesAll.Matches | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    if ($allDomains.Count -eq 0) {
        Write-Host "[-] No domains found in response. Likely not linked to Microsoft 365." -ForegroundColor Yellow
        return
    }

    Write-Host "`n[+] Domains associated with tenant:" -ForegroundColor Green
    $allDomains | ForEach-Object { Write-Host "  - $_" }

    $tenants = $allDomains | Where-Object { $_ -like "*.onmicrosoft.com" } | ForEach-Object { $_.Split('.')[0] } | Sort-Object -Unique

    foreach ($tenant in $tenants) {
        $onMicrosoftDomain = "$tenant.onmicrosoft.com"
        Write-Host "`n[+] Tenant Name: $tenant" -ForegroundColor Green
        Write-Host "[*] Validating $onMicrosoftDomain" -ForegroundColor Cyan

        $tenantMX = @()
        try {
            $tenantMX = (Resolve-DnsName -Name $onMicrosoftDomain -Type MX -ErrorAction Stop).NameExchange
            $tenantMX | ForEach-Object { Write-Host "[+] MX for $($onMicrosoftDomain): $_" -ForegroundColor Green }
            Write-Host "[!] This endpoint may be targetable via Direct Send and bypass the Secure Email Gateway (SEG)" -ForegroundColor Magenta
        } catch {
            $tenantMX = @("[-] Could not resolve")
            Write-Host "[-] Could not resolve MX for $onMicrosoftDomain" -ForegroundColor Yellow
        }

        $openid = $realm = $tokenEndpoint = $federationBrand = $tenantId = $null

        Write-Host "[*] Fetching OpenID configuration..." -ForegroundColor Cyan
        try {
            $openid = Invoke-RestMethod -Uri "https://login.windows.net/$Domain/.well-known/openid-configuration" -ErrorAction Stop
            $tokenEndpoint = $openid.token_endpoint
            Write-Host "[+] Token Endpoint: $tokenEndpoint" -ForegroundColor Green

            if ($tokenEndpoint -match "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})") {
                $tenantId = $Matches[1]
                Write-Host "[+] Tenant ID: $tenantId" -ForegroundColor Green
            } else {
                Write-Host "[-] Could not parse Tenant ID" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[-] Could not fetch OpenID config" -ForegroundColor Yellow
        }

        Write-Host "[*] Checking user realm for Federation brand..." -ForegroundColor Cyan
        try {
            $realm = Invoke-RestMethod "https://login.microsoftonline.com/getuserrealm.srf?login=test@$Domain" -ErrorAction Stop
            $federationBrand = $realm.FederationBrandName
            if ($federationBrand) {
                Write-Host "[+] Federation Brand: $federationBrand" -ForegroundColor Green
            } else {
                Write-Host "[-] No Federation Brand returned" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[-] Could not fetch Federation Brand" -ForegroundColor Yellow
        }

        Write-Host "[*] Probing for OWA..." -ForegroundColor Cyan
        $schemes = @("https", "http")
        $owaUrls = @(
            "autodiscover.$Domain/autodiscover/autodiscover.xml",
            "exchange.$Domain/autodiscover/autodiscover.xml",
            "webmail.$Domain/autodiscover/autodiscover.xml",
            "email.$Domain/autodiscover/autodiscover.xml",
            "mail.$Domain/autodiscover/autodiscover.xml",
            "owa.$Domain/autodiscover/autodiscover.xml",
            "mx.$Domain/autodiscover/autodiscover.xml",
            "$Domain/autodiscover/autodiscover.xml"
        )

        foreach ($mx in $originalMX) {
            $cleanMX = $mx.TrimEnd(".")
            $owaUrls += "$cleanMX/autodiscover/autodiscover.xml"
        }

        $owaUrls = $owaUrls | Sort-Object -Unique
        $owaHits = @()

        foreach ($scheme in $schemes) {
            foreach ($partial in $owaUrls) {
                $url = "${scheme}://${partial}"
                try {
                    $resp = Invoke-WebRequest -Uri $url -Method GET -TimeoutSec 2 -ErrorAction Stop
                    $headers = @{}
                    if ($resp.Headers) {
                        foreach ($k in $resp.Headers.Keys) {
                            $headers[$k.ToLower()] = $resp.Headers[$k]
                        }
                    }
                    if ($headers["x-owa-version"] -or ($headers["www-authenticate"] -match "NTLM")) {
                        Write-Host "[+] OWA endpoint discovered: $url" -ForegroundColor Green
                        $owaHits += $url
                    }
                } catch {
                    $errorResponse = $_.Exception.Response
                    if ($errorResponse -and $errorResponse.Headers) {
                        $headers = @{}
                        foreach ($k in $errorResponse.Headers.Keys) {
                            $headers[$k.ToLower()] = $errorResponse.Headers[$k]
                        }
                        if ($headers["x-owa-version"] -or ($headers["www-authenticate"] -match "NTLM")) {
                            Write-Host "[+] OWA endpoint discovered (from error): $url" -ForegroundColor Green
                            $owaHits += $url
                        }
                    }
                }
            }
        }

        if ($owaHits.Count -gt 0) {
            $owaHits | ForEach-Object { Write-Host "[+] OWA endpoint discovered: $_" -ForegroundColor Green }
        } else {
            Write-Host "[-] No Exchange (OWA) endpoints discovered" -ForegroundColor Yellow
        }

        Write-Host "[*] Attempting internal domain extraction via NTLM..." -ForegroundColor Cyan
        $ntlmEndpoints = @(
            "aspnet_client",
            "autodiscover",
            "autodiscover/autodiscover.xml",
            "ecp",
            "ews",
            "ews/exchange.asmx",
            "ews/services.wsdl",
            "exchange",
            "microsoft-server-activesync",
            "microsoft-server-activesync/default.eas",
            "oab",
            "owa",
            "powershell",
            "rpc"
        )

        $internalDomain = $null
        $baseUrl = $owaHits[0] -replace "/autodiscover.*", ""

        foreach ($endpoint in $ntlmEndpoints) {
            $targetUrl = "$baseUrl/$endpoint".ToLower()
            try {
                $ntlmHeaders = @{
                    Authorization = "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=="
                }

                $resp = Invoke-WebRequest -Uri $targetUrl -Method POST -Headers $ntlmHeaders -TimeoutSec 3 -ErrorAction Stop
            } catch {
                $resp = $_.Exception.Response
            }

            if ($resp -and $resp.Headers["WWW-Authenticate"] -match "NTLM\s+([A-Za-z0-9+/=]+)") {
                $base64 = $Matches[1]
                $bytes = [System.Convert]::FromBase64String($base64)

                # Decode the NTLM challenge as a UTF-16LE string
                $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes)

                # Try to find a fully qualified internal domain (e.g. services.company.com)
                if ($utf16 -match "(?i)([a-z0-9][a-z0-9\.-]+\.(local|com|internal|lan|corp|net))") {
                    $internalDomain = $Matches[1]
                    Write-Host "[+] Internal Domain (NTLM): $internalDomain" -ForegroundColor Green
                    break
                }

                # Fallback: try to extract NetBIOS-style domain (e.g. CORP)
                if (-not $internalDomain -and $utf16 -match "(?i)([A-Z0-9\-]{2,})\x00") {
                    $internalDomain = $Matches[1]
                    Write-Host "[+] Internal Domain (NTLM): $internalDomain" -ForegroundColor Green
                    break
                }
            }
        }

        if (-not $internalDomain) {
            Write-Host "[-] Could not determine internal domain from NTLM challenge." -ForegroundColor Yellow
        }

        Write-Host "[*] Checking if SharePoint Online is enabled for the tenant..." -ForegroundColor Cyan

        $spoRoot = "https://$tenant.sharepoint.com"
        $spoMy   = "https://$tenant-my.sharepoint.com"

        $spoRootUrls = @(
            "$spoRoot",
            "$spoRoot/_layouts/15/start.aspx",
            "$spoRoot/sites/dev",
            "$spoRoot/sites/test"
        )

        $spoMyUrls = @(
            "$spoMy",
            "$spoMy/_layouts/15/onedrive.aspx"
        )

        $spoDiscovered = $null
        $spoMyDiscovered = $null

        # Check SharePoint Online root
        foreach ($url in $spoRootUrls) {
            try {
                $resp = Invoke-WebRequest -Uri $url -Method HEAD -TimeoutSec 3 -ErrorAction Stop
                if ($resp.StatusCode -in 200, 302, 401, 403) {
                    $spoDiscovered = $url
                    break
                }
            } catch {
                $resp = $_.Exception.Response
                if ($resp -and $resp.StatusCode.value__ -in 401, 403, 302) {
                    $spoDiscovered = $url
                    break
                }
            }
        }

        # Check OneDrive MySite hosting
        foreach ($url in $spoMyUrls) {
            try {
                $resp = Invoke-WebRequest -Uri $url -Method HEAD -TimeoutSec 3 -ErrorAction Stop
                if ($resp.StatusCode -in 200, 302, 401, 403) {
                    $spoMyDiscovered = $url
                    break
                }
            } catch {
                $resp = $_.Exception.Response
                if ($resp -and $resp.StatusCode.value__ -in 401, 403, 302) {
                    $spoMyDiscovered = $url
                    break
                }
            }
        }

        if ($spoDiscovered) {
            Write-Host "[+] SharePoint Online (Root) appears active: $spoDiscovered" -ForegroundColor Green
        } else {
            Write-Host "[-] SharePoint Online (Root) not found" -ForegroundColor Yellow
        }

        if ($spoMyDiscovered) {
            Write-Host "[+] OneDrive hosting via SharePoint (MySite) appears active: $spoMyDiscovered" -ForegroundColor Green
        } else {
            Write-Host "[-] OneDrive MySite not found" -ForegroundColor Yellow
        }

        Write-Host "`n[*] Summary:`n"
        Format-KeyValueSummary -Key "TenantName" -Values $tenant
        Format-KeyValueSummary -Key "OnMicrosoftDomain" -Values $onMicrosoftDomain
        Format-KeyValueSummary -Key "TenantMXRecord" -Values $tenantMX
        Format-KeyValueSummary -Key "OriginalDomainMX" -Values $originalMX
        Format-KeyValueSummary -Key "TenantID" -Values @(if ($tenantId) { $tenantId } else { "[-] Unavailable" })
        Format-KeyValueSummary -Key "TokenEndpoint" -Values @(if ($tokenEndpoint) { $tokenEndpoint } else { "[-] Unavailable" })
        Format-KeyValueSummary -Key "FederationBrand" -Values @(if ($federationBrand) { $federationBrand } else { "[-] Unavailable" })
        Format-KeyValueSummary -Key "OWA Discovered" -Values @(if ($owaHits.Count -gt 0) { $owaHits } else { "[-] No Exchange (OWA) discovered" })
        Format-KeyValueSummary -Key "InternalDomain" -Values @(if ($internalDomain) { $internalDomain } else { "[-] Unavailable" })
    }

} catch {
    Write-Host "[-] Request failed: $($_.Exception.Message)`nLikely not a Microsoft 365 tenant." -ForegroundColor Red
}
