<#
.SYNOPSIS
    Verifica se um usuario ja existe no AD, se esta desativado, ou se ha nomes similares.
.DESCRIPTION
    Realiza uma busca completa no AD antes da criacao de um novo usuario.
.PARAMETER Login
    Login a ser verificado (SamAccountName)
.PARAMETER NomeCompleto
    Nome completo para busca de similares
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Login,
    
    [Parameter(Mandatory = $false)]
    [string]$NomeCompleto = ""
)

$resultado = @{
    login_verificado   = $Login
    nome_verificado    = $NomeCompleto
    usuario_existe     = $false
    usuario_desativado = $false
    usuarios_similares = @()
    pode_criar         = $true
    mensagens          = @()
}

try {
    # Verificar se o modulo ActiveDirectory esta disponivel
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "Modulo ActiveDirectory nao esta instalado."
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # 1. Verificar se o login exato ja existe
    $usuarioExato = Get-ADUser -Filter "SamAccountName -eq '$Login'" -Properties Enabled, DisplayName, Description, WhenCreated, LastLogonDate -ErrorAction SilentlyContinue
    
    if ($usuarioExato) {
        $resultado.usuario_existe = $true
        $resultado.pode_criar = $false
        
        $status = if ($usuarioExato.Enabled) { "ATIVO" } else { "DESATIVADO" }
        $resultado.usuario_desativado = -not $usuarioExato.Enabled
        
        $resultado.mensagens += "[AVISO] USUARIO JA EXISTE: $Login ($status)"
        $resultado.mensagens += "   Nome: $($usuarioExato.DisplayName)"
        $resultado.mensagens += "   Descricao: $($usuarioExato.Description)"
        $resultado.mensagens += "   Criado em: $($usuarioExato.WhenCreated)"
        $resultado.mensagens += "   Ultimo login: $($usuarioExato.LastLogonDate)"
    }
    else {
        $resultado.mensagens += "[OK] Login '$Login' esta disponivel."
    }
    
    # 2. Buscar usuarios com nomes similares
    if ($NomeCompleto -ne "") {
        $partes = $NomeCompleto.Trim() -split '\s+'
        $primeiroNome = $partes[0]
        $ultimoNome = if ($partes.Count -gt 1) { $partes[-1] } else { "" }
        
        # Busca por primeiro nome
        $similaresPrimeiroNome = Get-ADUser -Filter "GivenName -like '$primeiroNome*'" -Properties Enabled, DisplayName, SamAccountName, Department -ErrorAction SilentlyContinue | Select-Object -First 10
        
        # Busca por sobrenome
        $similaresUltimoNome = @()
        if ($ultimoNome -ne "") {
            $similaresUltimoNome = Get-ADUser -Filter "Surname -like '$ultimoNome*'" -Properties Enabled, DisplayName, SamAccountName, Department -ErrorAction SilentlyContinue | Select-Object -First 10
        }
        
        # Busca por nome completo (parcial)
        $similaresNomeCompleto = Get-ADUser -Filter "DisplayName -like '*$primeiroNome*'" -Properties Enabled, DisplayName, SamAccountName, Department -ErrorAction SilentlyContinue | Select-Object -First 10
        
        # Combinar e remover duplicados
        $todosSimilares = @()
        $loginsJaAdicionados = @{}
        
        foreach ($user in ($similaresPrimeiroNome + $similaresUltimoNome + $similaresNomeCompleto)) {
            if ($user -and -not $loginsJaAdicionados.ContainsKey($user.SamAccountName)) {
                $loginsJaAdicionados[$user.SamAccountName] = $true
                $status = if ($user.Enabled) { "ATIVO" } else { "DESATIVADO" }
                
                $todosSimilares += @{
                    login  = $user.SamAccountName
                    nome   = $user.DisplayName
                    setor  = $user.Department
                    status = $status
                    ativo  = $user.Enabled
                }
            }
        }
        
        $resultado.usuarios_similares = $todosSimilares
        
        if ($todosSimilares.Count -gt 0) {
            $resultado.mensagens += ""
            $resultado.mensagens += "[INFO] USUARIOS COM NOMES SIMILARES ENCONTRADOS: $($todosSimilares.Count)"
            $resultado.mensagens += ("-" * 60)
            
            foreach ($similar in $todosSimilares) {
                $statusIcon = if ($similar.ativo) { "[+]" } else { "[-]" }
                $resultado.mensagens += "$statusIcon $($similar.login) - $($similar.nome) [$($similar.status)]"
            }
        }
        else {
            $resultado.mensagens += ""
            $resultado.mensagens += "[INFO] Nenhum usuario com nome similar encontrado."
        }
    }
    
    # 3. Verificar logins similares (variacoes)
    if ($NomeCompleto -ne "" -and $partes.Count -gt 1) {
        $variacoes = @(
            "$($primeiroNome.ToLower()).$($ultimoNome.ToLower())",
            "$($primeiroNome.Substring(0,1).ToLower())$($ultimoNome.ToLower())",
            "$($primeiroNome.ToLower())$($ultimoNome.Substring(0,1).ToLower())"
        )
        
        $loginsSimilares = @()
        foreach ($variacao in $variacoes) {
            if ($variacao -ne $Login -and $variacao.Length -gt 2) {
                $userVariacao = Get-ADUser -Filter "SamAccountName -like '$variacao*'" -Properties Enabled, DisplayName -ErrorAction SilentlyContinue | Select-Object -First 5
                foreach ($u in $userVariacao) {
                    if ($u -and $u.SamAccountName -ne $Login) {
                        $status = if ($u.Enabled) { "ATIVO" } else { "DESATIVADO" }
                        $loginsSimilares += "$($u.SamAccountName) - $($u.DisplayName) [$status]"
                    }
                }
            }
        }
        
        if ($loginsSimilares.Count -gt 0) {
            $resultado.mensagens += ""
            $resultado.mensagens += "[INFO] LOGINS SIMILARES:"
            foreach ($ls in ($loginsSimilares | Select-Object -Unique)) {
                $resultado.mensagens += "   $ls"
            }
        }
    }
    
}
catch {
    $resultado.mensagens += "[ERRO] $($_.Exception.Message)"
    $resultado.pode_criar = $false
}

$resultado | ConvertTo-Json -Depth 3 -Compress
