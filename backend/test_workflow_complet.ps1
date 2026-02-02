# Script de test complet du workflow CTBA : CVEs -> Bulletin -> Email
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST WORKFLOW COMPLET CTBA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:8000"

# ============================================================================
# ETAPE 1 : CONNEXION
# ============================================================================
Write-Host "1. CONNEXION A L'API" -ForegroundColor Yellow
Write-Host "-------------------" -ForegroundColor Gray

try {
    $loginResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method POST `
        -ContentType "application/json" `
        -Body '{"username": "analyst1", "password": "password123"}'
    
    $token = $loginResponse.access_token
    Write-Host "   Connecte en tant que: analyst1" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "   ERREUR: Impossible de se connecter" -ForegroundColor Red
    Write-Host "   Verifiez que le backend est demarre" -ForegroundColor Red
    exit 1
}

# ============================================================================
# ETAPE 2 : RECUPERER LES CVES EN ATTENTE
# ============================================================================
Write-Host "2. RECUPERATION DES CVES EN ATTENTE" -ForegroundColor Yellow
Write-Host "------------------------------------" -ForegroundColor Gray

try {
    $cvesResponse = Invoke-RestMethod -Uri "$baseUrl/api/cves?decision=PENDING&limit=10" `
        -Headers @{Authorization = "Bearer $token"}
    
    $cves = $cvesResponse.cves
    Write-Host "   Trouve: $($cves.Count) CVEs en attente" -ForegroundColor Green
    
    if ($cves.Count -eq 0) {
        Write-Host "   Aucune CVE en attente pour le test" -ForegroundColor Yellow
        Write-Host "   Importez d'abord des CVEs avec /api/import/nvd ou /api/import/cvedetails" -ForegroundColor Yellow
        exit 0
    }
    
    # Afficher les 5 premiers CVEs
    Write-Host ""
    Write-Host "   CVEs disponibles:" -ForegroundColor Gray
    for ($i = 0; $i -lt [Math]::Min(5, $cves.Count); $i++) {
        $cve = $cves[$i]
        Write-Host "   - $($cve.cve_id) | $($cve.severity) ($($cve.score)) | $($cve.description.Substring(0, [Math]::Min(60, $cve.description.Length)))..." -ForegroundColor Gray
    }
    Write-Host ""
    
} catch {
    Write-Host "   ERREUR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# ETAPE 3 : ACCEPTER QUELQUES CVES
# ============================================================================
Write-Host "3. ACCEPTATION DE 3 CVES" -ForegroundColor Yellow
Write-Host "-------------------------" -ForegroundColor Gray

$acceptedCves = @()
$cvesToAccept = [Math]::Min(3, $cves.Count)

for ($i = 0; $i -lt $cvesToAccept; $i++) {
    $cve = $cves[$i]
    
    try {
        $updateBody = @{
            decision = "ACCEPTED"
            reviewer_comment = "CVE accepte pour bulletin de test"
        } | ConvertTo-Json
        
        $result = Invoke-RestMethod -Uri "$baseUrl/api/cves/$($cve.cve_id)" `
            -Method PUT `
            -Headers @{Authorization = "Bearer $token"} `
            -ContentType "application/json" `
            -Body $updateBody
        
        $acceptedCves += $cve.cve_id
        Write-Host "   $($cve.cve_id) - ACCEPTE" -ForegroundColor Green
        
    } catch {
        Write-Host "   $($cve.cve_id) - ERREUR" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "   Total accepte: $($acceptedCves.Count) CVEs" -ForegroundColor Green
Write-Host ""

# ============================================================================
# ETAPE 4 : CREER UN BULLETIN
# ============================================================================
Write-Host "4. CREATION DU BULLETIN" -ForegroundColor Yellow
Write-Host "-----------------------" -ForegroundColor Gray

# Construire le HTML du bulletin
$htmlBody = @"
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; color: white; text-align: center; }
        .content { padding: 30px; background: #f5f5f5; }
        .cve-item { background: white; padding: 15px; margin: 10px 0; border-left: 4px solid #667eea; }
        .severity-HIGH { border-left-color: #ff6b6b; }
        .severity-CRITICAL { border-left-color: #c92a2a; }
        .severity-MEDIUM { border-left-color: #ffa94d; }
        .footer { padding: 20px; text-align: center; color: #999; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Bulletin de Securite CTBA</h1>
        <p>Test du systeme de mailing</p>
    </div>
    
    <div class="content">
        <h2>Nouvelles vulnerabilites identifiees</h2>
        <p>Ce bulletin contient <strong>$($acceptedCves.Count)</strong> nouvelles vulnerabilites qui necessitent votre attention.</p>
        
        <h3>CVEs inclus dans ce bulletin:</h3>
"@

foreach ($cveId in $acceptedCves) {
    $cve = $cves | Where-Object { $_.cve_id -eq $cveId }
    $htmlBody += @"
        <div class="cve-item severity-$($cve.severity)">
            <h4>$($cve.cve_id) - $($cve.severity) (Score: $($cve.score))</h4>
            <p>$($cve.description)</p>
        </div>
"@
}

$htmlBody += @"
        
        <div style="margin-top: 30px; padding: 20px; background: #e3f2fd; border-left: 4px solid #2196f3;">
            <h3>Actions recommandees</h3>
            <ul>
                <li>Reviser les vulnerabilites listees ci-dessus</li>
                <li>Identifier les systemes impactes</li>
                <li>Planifier les correctifs necessaires</li>
                <li>Mettre a jour les systemes concernes</li>
            </ul>
        </div>
    </div>
    
    <div class="footer">
        <p>Plateforme CTBA v7.0.0</p>
        <p>Email envoye le: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')</p>
    </div>
</body>
</html>
"@

try {
    $bulletinBody = @{
        title = "Bulletin de Securite - $(Get-Date -Format 'dd/MM/yyyy') - $($acceptedCves.Count) CVEs"
        body = $htmlBody
        regions = @("NORAM")
        cve_ids = $acceptedCves
    } | ConvertTo-Json
    
    $bulletin = Invoke-RestMethod -Uri "$baseUrl/api/bulletins" `
        -Method POST `
        -Headers @{Authorization = "Bearer $token"} `
        -ContentType "application/json" `
        -Body $bulletinBody
    
    Write-Host "   Bulletin cree avec succes!" -ForegroundColor Green
    Write-Host "   ID: $($bulletin.id)" -ForegroundColor Gray
    Write-Host "   Titre: $($bulletin.title)" -ForegroundColor Gray
    Write-Host "   Regions: $($bulletin.regions -join ', ')" -ForegroundColor Gray
    Write-Host ""
    
} catch {
    Write-Host "   ERREUR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ============================================================================
# ETAPE 5 : CONFIRMER L'ENVOI
# ============================================================================
Write-Host "5. ENVOI DU BULLETIN PAR EMAIL" -ForegroundColor Yellow
Write-Host "-------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host "   L'email sera envoye a: $env:SMTP_FROM_EMAIL" -ForegroundColor Cyan
Write-Host "   (configure dans le fichier .env)" -ForegroundColor Gray
Write-Host ""
Write-Host "   Voulez-vous continuer ? (o/n): " -NoNewline -ForegroundColor Yellow
$confirmation = Read-Host

if ($confirmation -ne 'o' -and $confirmation -ne 'O') {
    Write-Host "   Envoi annule" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   Le bulletin (ID: $($bulletin.id)) reste en statut DRAFT" -ForegroundColor Gray
    Write-Host "   Vous pouvez l'envoyer plus tard via: POST /api/bulletins/$($bulletin.id)/send" -ForegroundColor Gray
    exit 0
}

# ============================================================================
# ETAPE 6 : ENVOYER LE BULLETIN
# ============================================================================
Write-Host ""
Write-Host "   Envoi en cours..." -ForegroundColor Yellow

try {
    $sendResult = Invoke-RestMethod -Uri "$baseUrl/api/bulletins/$($bulletin.id)/send" `
        -Method POST `
        -Headers @{Authorization = "Bearer $token"} `
        -ContentType "application/json" `
        -Body '{}'
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "BULLETIN ENVOYE AVEC SUCCES !" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "   Bulletin ID: $($sendResult.bulletin_id)" -ForegroundColor Gray
    Write-Host "   Regions traitees: $($sendResult.total_regions)" -ForegroundColor Gray
    Write-Host "   Envois reussis: $($sendResult.successful)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "   Details par region:" -ForegroundColor Gray
    foreach ($result in $sendResult.results) {
        if ($result.status -eq 'success') {
            Write-Host "   - $($result.region): $($result.recipients_count) destinataire(s)" -ForegroundColor Green
        } else {
            Write-Host "   - $($result.region): ERREUR - $($result.error)" -ForegroundColor Red
        }
    }
    
} catch {
    Write-Host ""
    Write-Host "   ERREUR lors de l'envoi:" -ForegroundColor Red
    Write-Host "   $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    
    # Afficher plus de details si disponible
    if ($_.ErrorDetails.Message) {
        Write-Host "   Details:" -ForegroundColor Yellow
        Write-Host "   $($_.ErrorDetails.Message)" -ForegroundColor Gray
    }
    exit 1
}

# ============================================================================
# ETAPE 7 : VERIFIER L'HISTORIQUE
# ============================================================================
Write-Host ""
Write-Host "6. VERIFICATION DE L'HISTORIQUE" -ForegroundColor Yellow
Write-Host "--------------------------------" -ForegroundColor Gray

try {
    $history = Invoke-RestMethod -Uri "$baseUrl/api/bulletins/$($bulletin.id)/delivery-history" `
        -Headers @{Authorization = "Bearer $token"}
    
    Write-Host "   Historique recupere: $($history.count) entree(s)" -ForegroundColor Green
    Write-Host ""
    
    foreach ($entry in $history.history) {
        Write-Host "   [$($entry.created_at)] $($entry.action) -> $($entry.region)" -ForegroundColor Gray
        if ($entry.message) {
            Write-Host "      Message: $($entry.message)" -ForegroundColor DarkGray
        }
    }
    
} catch {
    Write-Host "   Impossible de recuperer l'historique" -ForegroundColor Yellow
}

# ============================================================================
# RESUME FINAL
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TEST TERMINE AVEC SUCCES" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Resume de ce qui a ete fait:" -ForegroundColor White
Write-Host "   $($acceptedCves.Count) CVEs acceptes" -ForegroundColor Gray
Write-Host "   1 Bulletin cree (ID: $($bulletin.id))" -ForegroundColor Gray
Write-Host "   1 Email envoye avec succes" -ForegroundColor Gray
Write-Host ""
Write-Host "Prochaines etapes:" -ForegroundColor Yellow
Write-Host "   1. Verifiez votre boite email: $env:SMTP_FROM_EMAIL" -ForegroundColor Gray
Write-Host "      (L'email peut prendre 1-2 minutes)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   2. Dans 7 jours, un rappel automatique sera envoye" -ForegroundColor Gray
Write-Host "   3. Dans 14 jours, un deuxieme rappel sera envoye" -ForegroundColor Gray
Write-Host "   4. Dans 30 jours, une escalation sera envoyee" -ForegroundColor Gray
Write-Host ""
Write-Host "Pour fermer manuellement le bulletin:" -ForegroundColor Yellow
Write-Host "   POST $baseUrl/api/bulletins/$($bulletin.id)/close" -ForegroundColor Gray
Write-Host ""
Write-Host "Pour voir les analytics:" -ForegroundColor Yellow
Write-Host "   GET $baseUrl/api/analytics/operational-dashboard" -ForegroundColor Gray
Write-Host "   GET $baseUrl/api/analytics/bulletin-timelines" -ForegroundColor Gray
Write-Host ""
