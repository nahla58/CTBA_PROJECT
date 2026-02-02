# Test simple du système de mailing CTBA
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST DU SYSTEME DE MAILING CTBA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Charger les variables d'environnement
Write-Host "Chargement configuration SMTP..." -ForegroundColor Yellow
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$' -and -not $_.StartsWith('#')) {
        $name = $matches[1].Trim()
        $value = $matches[2].Trim()
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

Write-Host "Configuration chargee:" -ForegroundColor Green
Write-Host "  SMTP Server: $env:SMTP_SERVER" -ForegroundColor Gray
Write-Host "  SMTP Port: $env:SMTP_PORT" -ForegroundColor Gray
Write-Host "  From Email: $env:SMTP_FROM_EMAIL" -ForegroundColor Gray
Write-Host ""

Write-Host "Demarrage du backend..." -ForegroundColor Yellow
Write-Host "Attendez 15 secondes pour que le serveur demarre..." -ForegroundColor Yellow
Write-Host ""

$backendJob = Start-Job -ScriptBlock {
    Set-Location "C:\essai\CTBA_PROJECT\backend"
    Get-Content .env | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$' -and -not $_.StartsWith('#')) {
            [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
        }
    }
    python main.py
}

Start-Sleep -Seconds 15

# Test connexion
Write-Host "Connexion a l'API..." -ForegroundColor Yellow
try {
    $loginResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/login" -Method POST -ContentType "application/json" -Body '{"username": "analyst1", "password": "password123"}'
    $token = $loginResponse.access_token
    Write-Host "Connecte avec succes !" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "Erreur de connexion: $($_.Exception.Message)" -ForegroundColor Red
    Stop-Job -Job $backendJob
    Remove-Job -Job $backendJob
    exit 1
}

# Creation bulletin
Write-Host "Creation du bulletin de test..." -ForegroundColor Yellow
$htmlBody = "<html><body><h1>Test Email CTBA</h1><p>Ceci est un email de test du systeme de mailing CTBA.</p><p>Si vous recevez cet email, votre configuration fonctionne correctement !</p></body></html>"

$bulletinData = @{
    title = "TEST - Bulletin de Securite CTBA"
    body = $htmlBody
    regions = @("NORAM")
} | ConvertTo-Json

try {
    $bulletin = Invoke-RestMethod -Uri "http://localhost:8000/api/bulletins" -Method POST -Headers @{Authorization = "Bearer $token"} -ContentType "application/json" -Body $bulletinData
    Write-Host "Bulletin cree avec succes (ID: $($bulletin.id))" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "Erreur creation bulletin: $($_.Exception.Message)" -ForegroundColor Red
    Stop-Job -Job $backendJob
    Remove-Job -Job $backendJob
    exit 1
}

# Envoi bulletin
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "ATTENTION: L'email sera envoye a: $env:SMTP_FROM_EMAIL" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Voulez-vous continuer ? (o/n): " -NoNewline
$confirmation = Read-Host

if ($confirmation -ne 'o') {
    Write-Host "Test annule" -ForegroundColor Red
    Stop-Job -Job $backendJob
    Remove-Job -Job $backendJob
    exit 0
}

Write-Host ""
Write-Host "Envoi du bulletin..." -ForegroundColor Yellow

try {
    $sendResult = Invoke-RestMethod -Uri "http://localhost:8000/api/bulletins/$($bulletin.id)/send" -Method POST -Headers @{Authorization = "Bearer $token"} -ContentType "application/json" -Body '{}'
    
    Write-Host ""
    Write-Host "========================================"  -ForegroundColor Green
    Write-Host "BULLETIN ENVOYE AVEC SUCCES !" -ForegroundColor Green
    Write-Host "========================================"  -ForegroundColor Green
    Write-Host "  Regions traitees: $($sendResult.total_regions)" -ForegroundColor Gray
    Write-Host "  Envois reussis: $($sendResult.successful)" -ForegroundColor Gray
    Write-Host ""
    
    foreach ($result in $sendResult.results) {
        if ($result.status -eq 'success') {
            Write-Host "  $($result.region): $($result.recipients_count) destinataire(s)" -ForegroundColor Green
        } else {
            Write-Host "  $($result.region): ERREUR - $($result.error)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "Verifiez votre boite email: $env:SMTP_FROM_EMAIL" -ForegroundColor Yellow
    Write-Host "(L'email peut prendre quelques minutes)" -ForegroundColor Gray
    
} catch {
    Write-Host "Erreur lors de l'envoi:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Logs du backend:" -ForegroundColor Yellow
    Receive-Job -Job $backendJob | Select-Object -Last 30
}

Write-Host ""
Write-Host "Appuyez sur une touche pour arreter le backend..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Stop-Job -Job $backendJob
Remove-Job -Job $backendJob
Write-Host "Backend arrete" -ForegroundColor Green
