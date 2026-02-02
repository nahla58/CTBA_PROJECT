# Script PowerShell pour démarrer le backend CTBA avec configuration mailing
# Usage: .\start_backend_with_mailing.ps1

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🚀 DÉMARRAGE BACKEND CTBA AVEC MAILING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier si .env existe
if (Test-Path ".env") {
    Write-Host "✅ Fichier .env trouvé, chargement des variables SMTP..." -ForegroundColor Green
    
    # Charger les variables d'environnement depuis .env
    Get-Content .env | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$' -and -not $_.StartsWith('#')) {
            $name = $matches[1].Trim()
            $value = $matches[2].Trim()
            [Environment]::SetEnvironmentVariable($name, $value, "Process")
            Write-Host "   Chargé: $name" -ForegroundColor Gray
        }
    }
    Write-Host ""
} else {
    Write-Host "⚠️  Fichier .env non trouvé" -ForegroundColor Yellow
    Write-Host "   Le système fonctionnera en MODE SIMULATION (emails loggés uniquement)" -ForegroundColor Yellow
    Write-Host "   Pour activer l'envoi réel d'emails:" -ForegroundColor Yellow
    Write-Host "   1. Copiez .env.example en .env" -ForegroundColor Yellow
    Write-Host "   2. Modifiez les valeurs SMTP" -ForegroundColor Yellow
    Write-Host "   3. Relancez ce script" -ForegroundColor Yellow
    Write-Host ""
}

# Vérifier les régions
Write-Host "📊 Vérification de la base de données..." -ForegroundColor Cyan
$checkScript = @"
import sqlite3
conn = sqlite3.connect('ctba_platform.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) FROM regions')
count = cursor.fetchone()[0]
print(f'{count}')
conn.close()
"@

$regionCount = python -c $checkScript

if ($regionCount -gt 0) {
    Write-Host "✅ $regionCount région(s) configurée(s)" -ForegroundColor Green
} else {
    Write-Host "❌ Aucune région trouvée !" -ForegroundColor Red
    Write-Host "   Exécutez d'abord: python init_regions.py" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🎯 CONFIGURATION DU MAILING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Afficher la configuration SMTP actuelle
$smtpServer = $env:SMTP_SERVER
$smtpPort = $env:SMTP_PORT
$smtpFrom = $env:SMTP_FROM_EMAIL

if ($smtpServer) {
    Write-Host "📧 SMTP Server: $smtpServer:$smtpPort" -ForegroundColor Green
    Write-Host "📧 From Email:  $smtpFrom" -ForegroundColor Green
    Write-Host "✅ Mode: ENVOI RÉEL D'EMAILS" -ForegroundColor Green
} else {
    Write-Host "📧 SMTP: Non configuré" -ForegroundColor Yellow
    Write-Host "⚠️  Mode: SIMULATION (emails loggés uniquement)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🌐 Démarrage du serveur..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Démarrer le backend
python main.py
