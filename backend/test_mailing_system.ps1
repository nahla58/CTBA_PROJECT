# Script de test du système de mailing CTBA
# Ce script teste l'envoi d'un bulletin par email

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🧪 TEST DU SYSTÈME DE MAILING CTBA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Charger les variables d'environnement depuis .env
Write-Host "📋 Chargement de la configuration SMTP..." -ForegroundColor Yellow
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$' -and -not $_.StartsWith('#')) {
        $name = $matches[1].Trim()
        $value = $matches[2].Trim()
        [Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

Write-Host "✅ Configuration chargée:" -ForegroundColor Green
Write-Host "   SMTP Server: $env:SMTP_SERVER" -ForegroundColor Gray
Write-Host "   SMTP Port: $env:SMTP_PORT" -ForegroundColor Gray
Write-Host "   From Email: $env:SMTP_FROM_EMAIL" -ForegroundColor Gray
Write-Host ""

# Démarrer le backend en arrière-plan
Write-Host "🚀 Démarrage du backend..." -ForegroundColor Yellow
$backendJob = Start-Job -ScriptBlock {
    Set-Location "C:\essai\CTBA_PROJECT\backend"
    
    # Charger les variables d'environnement dans le job
    Get-Content .env | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$' -and -not $_.StartsWith('#')) {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
        }
    }
    
    python main.py
}

Write-Host "⏳ Attente du démarrage du serveur (15 secondes)..." -ForegroundColor Yellow
Start-Sleep -Seconds 15

# Vérifier que le serveur est démarré
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/docs" -TimeoutSec 5
    Write-Host "✅ Backend démarré avec succès !" -ForegroundColor Green
} catch {
    Write-Host "❌ Le backend ne répond pas. Vérifiez les logs ci-dessous:" -ForegroundColor Red
    Receive-Job -Job $backendJob
    Stop-Job -Job $backendJob
    Remove-Job -Job $backendJob
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🔐 ÉTAPE 1: Connexion" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$loginResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/login" `
    -Method POST `
    -ContentType "application/json" `
    -Body '{"username": "analyst1", "password": "password123"}'

$token = $loginResponse.access_token
Write-Host "✅ Connecté en tant que: analyst1" -ForegroundColor Green
Write-Host "   Token: $($token.Substring(0,20))..." -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "📝 ÉTAPE 2: Création du bulletin de test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$bulletinBody = @{
    title = "🧪 TEST - Bulletin de Sécurité CTBA"
    body = @"
<html>
<body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
    <div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center;'>
        <h1 style='color: white; margin: 0;'>🛡️ Bulletin de Sécurité CTBA</h1>
        <p style='color: #e0e0e0; margin: 10px 0 0 0;'>Système de Test</p>
    </div>
    
    <div style='padding: 30px; background: #f5f5f5;'>
        <h2 style='color: #333;'>Ceci est un email de test</h2>
        
        <p style='color: #666; line-height: 1.6;'>
            Bonjour,<br><br>
            Cet email confirme que votre système de mailing CTBA fonctionne correctement.
        </p>
        
        <div style='background: white; padding: 20px; border-left: 4px solid #667eea; margin: 20px 0;'>
            <h3 style='color: #667eea; margin-top: 0;'>✅ Fonctionnalités testées</h3>
            <ul style='color: #666;'>
                <li>Configuration SMTP Gmail</li>
                <li>Création de bulletins</li>
                <li>Envoi multi-régions</li>
                <li>Templates HTML</li>
            </ul>
        </div>
        
        <p style='color: #666; line-height: 1.6;'>
            Si vous recevez cet email, votre système est <strong>opérationnel</strong> ! 🎉
        </p>
        
        <div style='margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd;'>
            <p style='color: #999; font-size: 12px; margin: 0;'>
                Plateforme CTBA v7.0.0<br>
                Email envoyé le: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')
            </p>
        </div>
    </div>
</body>
</html>
"@
    regions = @("NORAM")
} | ConvertTo-Json

$bulletin = Invoke-RestMethod -Uri "http://localhost:8000/api/bulletins" `
    -Method POST `
    -Headers @{Authorization = "Bearer $token"} `
    -ContentType "application/json" `
    -Body $bulletinBody

Write-Host "✅ Bulletin créé avec succès !" -ForegroundColor Green
Write-Host "   ID: $($bulletin.id)" -ForegroundColor Gray
Write-Host "   Titre: $($bulletin.title)" -ForegroundColor Gray
Write-Host "   Régions: $($bulletin.regions -join ', ')" -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "📧 ÉTAPE 3: Envoi du bulletin" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  L'email sera envoyé à: $env:SMTP_FROM_EMAIL" -ForegroundColor Yellow
Write-Host ""
Write-Host "Voulez-vous continuer ? (o/n): " -NoNewline -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -ne 'o' -and $confirmation -ne 'O') {
    Write-Host "❌ Test annulé" -ForegroundColor Red
    Stop-Job -Job $backendJob
    Remove-Job -Job $backendJob
    exit 0
}

try {
    $sendResult = Invoke-RestMethod -Uri "http://localhost:8000/api/bulletins/$($bulletin.id)/send" `
        -Method POST `
        -Headers @{Authorization = "Bearer $token"} `
        -ContentType "application/json" `
        -Body '{}'
    
    Write-Host ""
    Write-Host "✅ Bulletin envoyé avec succès !" -ForegroundColor Green
    Write-Host "   Régions traitées: $($sendResult.total_regions)" -ForegroundColor Gray
    Write-Host "   Envois réussis: $($sendResult.successful)" -ForegroundColor Gray
    Write-Host ""
    
    foreach ($result in $sendResult.results) {
        if ($result.status -eq 'success') {
            Write-Host "   ✅ $($result.region): $($result.recipients_count) destinataire(s)" -ForegroundColor Green
        } else {
            Write-Host "   ❌ $($result.region): $($result.error)" -ForegroundColor Red
        }
    }
    
} catch {
    Write-Host "❌ Erreur lors de l'envoi:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    
    # Afficher les logs du backend
    Write-Host ""
    Write-Host "📋 Logs du backend:" -ForegroundColor Yellow
    Receive-Job -Job $backendJob | Select-Object -Last 20
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "📊 ÉTAPE 4: Vérification de l'historique" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$history = Invoke-RestMethod -Uri "http://localhost:8000/api/bulletins/$($bulletin.id)/delivery-history" `
    -Headers @{Authorization = "Bearer $token"}

Write-Host "✅ Historique récupéré: $($history.count) entrée(s)" -ForegroundColor Green
foreach ($entry in $history.history) {
    Write-Host "   - $($entry.action) → $($entry.region) [$($entry.created_at)]" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ TEST TERMINÉ" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📧 Vérifiez votre boîte email: $env:SMTP_FROM_EMAIL" -ForegroundColor Yellow
Write-Host "   (L'email peut prendre quelques minutes à arriver)" -ForegroundColor Gray
Write-Host ""
Write-Host "🔍 Pour voir les logs du backend:" -ForegroundColor Yellow
Write-Host "   Receive-Job -Job `$backendJob" -ForegroundColor Gray
Write-Host ""
Write-Host "⏹️  Pour arrêter le backend:" -ForegroundColor Yellow
Write-Host "   Stop-Job -Job `$backendJob; Remove-Job -Job `$backendJob" -ForegroundColor Gray
Write-Host ""

# Garder le script ouvert pour voir les logs
Write-Host "Appuyez sur une touche pour arrêter le backend et fermer..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

Stop-Job -Job $backendJob
Remove-Job -Job $backendJob
Write-Host "✅ Backend arrêté" -ForegroundColor Green
