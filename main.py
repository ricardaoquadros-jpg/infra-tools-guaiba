"""
Infra Tools Guaíba - Aplicativo de Automação TI
Prefeitura Municipal de Guaíba

Aplicativo portátil para:
- Criação automatizada de usuários no Active Directory
- Execução de scripts PowerShell pré-aprovados
- Logs de auditoria completos
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import json
import os
import sys
import unicodedata
import string
import random
import re
import threading
from datetime import datetime
from pathlib import Path


class InfraToolsApp:
    """Aplicativo principal de automação de TI."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Infra Tools Guaíba - Automação TI")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Definir diretório base (onde o executável está)
        if getattr(sys, 'frozen', False):
            self.base_dir = Path(sys.executable).parent
        else:
            self.base_dir = Path(__file__).parent
        
        # Carregar configurações
        self.config = self.load_config()
        
        # Verificar ambiente
        self.ambiente_ok = False
        self.info_ambiente = {}
        
        # Criar interface
        self.create_widgets()
        
        # Verificar ambiente ao iniciar
        self.root.after(100, self.verificar_ambiente)
    
    def load_config(self):
        """Carrega configurações do arquivo JSON."""
        config_path = self.base_dir / "config" / "settings.json"
        default_config = {
            "domain": "GUAIBA.LOCAL",
            "ous": {
                "Administrativo": "OU=Usuarios,OU=Administrativo,DC=GUAIBA,DC=LOCAL",
                "Educacao": "OU=Usuarios,OU=Educacao,DC=GUAIBA,DC=LOCAL",
                "Saude": "OU=Usuarios,OU=Saude,DC=GUAIBA,DC=LOCAL"
            },
            "grupos_padrao": [],
            "grupos_por_setor": {},
            "senha": {
                "tamanho": 12,
                "incluir_maiusculas": True,
                "incluir_minusculas": True,
                "incluir_numeros": True,
                "incluir_especiais": True
            },
            "dry_run": False
        }
        
        try:
            if config_path.exists():
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Mesclar com padrões
                    for key in default_config:
                        if key not in config:
                            config[key] = default_config[key]
                    return config
        except Exception as e:
            self.log_evento("ERRO", f"Falha ao carregar configurações: {e}")
        
        return default_config
    
    def get_cred_file_path(self):
        """Retorna o caminho do arquivo de credenciais."""
        return self.base_dir / "config" / ".cred_admin.xml"
    
    def tem_credencial_salva(self):
        """Verifica se existe credencial salva."""
        return self.get_cred_file_path().exists()
    
    def salvar_credencial_via_powershell(self):
        """Abre dialog para salvar credenciais usando PowerShell (em thread separada)."""
        cred_file = self.get_cred_file_path()
        
        # Executar em thread separada para não travar a interface
        def executar_salvar():
            ps_cmd = f"""
$cred = Get-Credential -Message 'Digite suas credenciais de ADMIN para o servidor AD'
if ($cred) {{
    $cred | Export-Clixml -Path '{cred_file}'
    Write-Output 'SUCESSO'
}} else {{
    Write-Output 'CANCELADO'
}}
"""
            
            try:
                resultado = subprocess.run(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if "SUCESSO" in resultado.stdout:
                    self.root.after(0, lambda: self._credencial_salva_sucesso())
                else:
                    self.root.after(0, lambda: messagebox.showwarning("Aviso", "Operação cancelada."))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Erro", f"Erro ao salvar credenciais: {e}"))
        
        thread = threading.Thread(target=executar_salvar, daemon=True)
        thread.start()
        return True  # Retorna imediatamente, o resultado vem via callback
    
    def _credencial_salva_sucesso(self):
        """Callback quando credencial é salva com sucesso."""
        messagebox.showinfo("Sucesso", "Credenciais salvas! Agora você não precisará digitar a senha novamente.")
        self.atualizar_status_credencial()
    
    def remover_credencial(self):
        """Remove credencial salva."""
        cred_file = self.get_cred_file_path()
        if cred_file.exists():
            cred_file.unlink()
            messagebox.showinfo("Removido", "Credenciais removidas com sucesso.")
        else:
            messagebox.showinfo("Info", "Nenhuma credencial salva encontrada.")
    
    def get_ps_credential_cmd(self):
        """Retorna comando PowerShell para obter credencial (salva ou Get-Credential com fallback)."""
        cred_file = self.get_cred_file_path()
        if cred_file.exists():
            # Tentar carregar credencial salva, com fallback para Get-Credential se falhar
            return f"""
try {{
    $cred = Import-Clixml -Path '{cred_file}'
    if (-not $cred) {{ throw 'Credencial nula' }}
}} catch {{
    Write-Host 'Credencial salva invalida, solicitando novamente...'
    $cred = Get-Credential -Message 'Credenciais de ADMIN para o servidor AD'
}}
"""
        else:
            return "$cred = Get-Credential -Message 'Credenciais de ADMIN para o servidor AD'"
    
    def atualizar_status_credencial(self):
        """Atualiza o status visual das credenciais salvas."""
        if hasattr(self, 'lbl_cred_status'):
            if self.tem_credencial_salva():
                self.lbl_cred_status.config(text="✅ Credenciais SALVAS - execução remota automática", foreground="green")
            else:
                self.lbl_cred_status.config(text="⚠️ Nenhuma credencial salva - será solicitada a cada execução", foreground="orange")
    
    def salvar_e_atualizar_credencial(self):
        """Salva credencial e atualiza a UI."""
        if self.salvar_credencial_via_powershell():
            self.atualizar_status_credencial()
    
    def remover_e_atualizar_credencial(self):
        """Remove credencial e atualiza a UI."""
        self.remover_credencial()
        self.atualizar_status_credencial()
    
    def create_widgets(self):
        """Cria todos os widgets da interface."""
        # Frame de status do ambiente
        self.status_frame = ttk.Frame(self.root, padding="5")
        self.status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(
            self.status_frame, 
            text="⏳ Verificando ambiente...",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Checkbox Dry Run
        self.dry_run_var = tk.BooleanVar(value=self.config.get("dry_run", False))
        self.dry_run_check = ttk.Checkbutton(
            self.status_frame,
            text="🧪 Modo Simulação (Dry Run)",
            variable=self.dry_run_var
        )
        self.dry_run_check.pack(side=tk.RIGHT, padx=10)
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Aba 1: Novo Usuário (fluxo completo)
        self.tab_novo_usuario = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.tab_novo_usuario, text="➕ Novo Usuário")
        self.create_novo_usuario_tab()
        
        # Aba 2: Executar Scripts
        self.tab_scripts = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.tab_scripts, text="📜 Scripts")
        self.create_scripts_tab()
        
        # Aba 3: Conectar ao Servidor
        self.tab_servidor = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.tab_servidor, text="🖥️ Servidor")
        self.create_servidor_tab()
        
        # Aba 4: Logs
        self.tab_logs = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.tab_logs, text="📋 Logs")
        self.create_logs_tab()
        
        # Frame de resultado/console
        self.console_frame = ttk.LabelFrame(self.root, text="Console de Saída", padding="5")
        self.console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.console = scrolledtext.ScrolledText(
            self.console_frame, 
            height=8, 
            font=("Consolas", 9),
            state=tk.DISABLED
        )
        self.console.pack(fill=tk.BOTH, expand=True)
        
        # Botões do console
        btn_frame = ttk.Frame(self.console_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="📋 Copiar Saída",
            command=self.copiar_console
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
        ).pack(side=tk.LEFT, padx=2)
    
    def create_novo_usuario_tab(self):
        """Cria a aba de novo usuário com fluxo de 3 passos."""
        
        # Frame principal com scroll
        main_frame = ttk.Frame(self.tab_novo_usuario)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # =====================================================
        # PASSO 1: COLAR EMAIL
        # =====================================================
        step1_frame = ttk.LabelFrame(main_frame, text="📧 PASSO 1: Colar Email", padding="10")
        step1_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(
            step1_frame,
            text="Cole o email completo abaixo e clique em 'Extrair Dados':",
            font=("Segoe UI", 10)
        ).pack(anchor=tk.W)
        
        self.email_text_novo = scrolledtext.ScrolledText(step1_frame, height=6, font=("Consolas", 9))
        self.email_text_novo.pack(fill=tk.X, pady=5)
        
        btn_frame1 = ttk.Frame(step1_frame)
        btn_frame1.pack(fill=tk.X)
        
        ttk.Button(
            btn_frame1,
            text="📋 Colar",
            command=self.colar_email_novo
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame1,
            text="🔍 Extrair Dados",
            command=self.extrair_dados_novo
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame1,
            text="🧹 Limpar",
            command=lambda: self.email_text_novo.delete(1.0, tk.END)
        ).pack(side=tk.LEFT, padx=2)
        
        # =====================================================
        # PASSO 2: DADOS EXTRAÍDOS + VERIFICAÇÃO
        # =====================================================
        step2_frame = ttk.LabelFrame(main_frame, text="🔎 PASSO 2: Verificar Usuário", padding="10")
        step2_frame.pack(fill=tk.X, pady=5)
        
        # Campos extraídos
        campos_frame = ttk.Frame(step2_frame)
        campos_frame.pack(fill=tk.X)
        
        # Linha 1: Nome e Login
        ttk.Label(campos_frame, text="Nome:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.entry_nome_novo = ttk.Entry(campos_frame, width=40)
        self.entry_nome_novo.grid(row=0, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(campos_frame, text="Login:").grid(row=0, column=2, sticky=tk.W, pady=2, padx=(20,0))
        self.entry_login_novo = ttk.Entry(campos_frame, width=25)
        self.entry_login_novo.grid(row=0, column=3, sticky=tk.W, pady=2, padx=5)
        
        # Linha 2: Setor e Cargo
        ttk.Label(campos_frame, text="Setor:").grid(row=1, column=0, sticky=tk.W, pady=2)
        setores = list(self.config.get("ous", {}).keys())
        self.combo_setor_novo = ttk.Combobox(campos_frame, values=setores, width=38, state="readonly")
        self.combo_setor_novo.grid(row=1, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(campos_frame, text="Cargo:").grid(row=1, column=2, sticky=tk.W, pady=2, padx=(20,0))
        self.entry_cargo_novo = ttk.Entry(campos_frame, width=25)
        self.entry_cargo_novo.grid(row=1, column=3, sticky=tk.W, pady=2, padx=5)
        
        # Linha 3: CPF e Telefone
        ttk.Label(campos_frame, text="CPF:").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.entry_cpf_novo = ttk.Entry(campos_frame, width=20)
        self.entry_cpf_novo.grid(row=2, column=1, sticky=tk.W, pady=2, padx=5)
        
        ttk.Label(campos_frame, text="Telefone:").grid(row=2, column=2, sticky=tk.W, pady=2, padx=(20,0))
        self.entry_telefone_novo = ttk.Entry(campos_frame, width=20)
        self.entry_telefone_novo.grid(row=2, column=3, sticky=tk.W, pady=2, padx=5)
        
        # Linha 4: Email (gerado automaticamente)
        ttk.Label(campos_frame, text="Email:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.label_email_novo = ttk.Label(campos_frame, text="(será gerado: login@guaiba.rs.gov.br)", font=("Consolas", 9), foreground="gray")
        self.label_email_novo.grid(row=3, column=1, columnspan=3, sticky=tk.W, pady=2, padx=5)
        
        # Botão verificar
        btn_frame2 = ttk.Frame(step2_frame)
        btn_frame2.pack(fill=tk.X, pady=10)
        
        self.btn_verificar_novo = ttk.Button(
            btn_frame2,
            text="🔎 VERIFICAR SE USUÁRIO EXISTE (Local)",
            command=self.verificar_usuario_novo,
            style="Accent.TButton"
        )
        self.btn_verificar_novo.pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame2,
            text="🚀 Verificar Remotamente",
            command=self.verificar_usuario_remoto
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame2,
            text="📋 Copiar Comando (Manual)",
            command=self.copiar_comando_verificacao
        ).pack(side=tk.LEFT, padx=5)
        
        # Resultado da verificação
        self.verificacao_result = scrolledtext.ScrolledText(step2_frame, height=5, font=("Consolas", 9))
        self.verificacao_result.pack(fill=tk.X, pady=5)
        self.verificacao_result.insert(tk.END, "⏳ Aguardando verificação...")
        self.verificacao_result.config(state=tk.DISABLED)
        
        # Status da verificação
        self.status_verificacao = ttk.Label(
            step2_frame,
            text="Status: Aguardando...",
            font=("Segoe UI", 10, "bold")
        )
        self.status_verificacao.pack(anchor=tk.W)
        
        # =====================================================
        # PASSO 3: CRIAR USUÁRIO
        # =====================================================
        step3_frame = ttk.LabelFrame(main_frame, text="✅ PASSO 3: Criar Usuário", padding="10")
        step3_frame.pack(fill=tk.X, pady=5)
        
        # OU de destino
        ou_frame = ttk.Frame(step3_frame)
        ou_frame.pack(fill=tk.X)
        
        ttk.Label(ou_frame, text="OU de Destino:").pack(side=tk.LEFT)
        self.label_ou_destino = ttk.Label(ou_frame, text="(selecione um setor)", font=("Consolas", 9))
        self.label_ou_destino.pack(side=tk.LEFT, padx=10)
        
        # Modo simulação
        self.dry_run_var_novo = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            step3_frame,
            text="🧪 Modo Simulação (dry-run) - não cria de verdade",
            variable=self.dry_run_var_novo
        ).pack(anchor=tk.W, pady=5)
        
        # Botão criar
        btn_frame3 = ttk.Frame(step3_frame)
        btn_frame3.pack(fill=tk.X, pady=5)
        
        self.btn_criar_novo = ttk.Button(
            btn_frame3,
            text="✅ CRIAR USUÁRIO NO AD (Gerar Comando)",
            command=self.criar_usuario_novo,
            style="Accent.TButton"
        )
        self.btn_criar_novo.pack(side=tk.LEFT, padx=5)
        
        self.btn_executar_remoto = ttk.Button(
            btn_frame3,
            text="🚀 Executar no Servidor (Remoto)",
            command=self.executar_comando_remoto
        )
        self.btn_executar_remoto.pack(side=tk.LEFT, padx=5)
        self.btn_criar_novo.config(state=tk.DISABLED)  # Desabilitado até verificar
        
        # Resultado
        self.resultado_criacao = scrolledtext.ScrolledText(step3_frame, height=4, font=("Consolas", 9))
        self.resultado_criacao.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            step3_frame,
            text="📋 Copiar Resultado",
            command=self.copiar_resultado_novo
        ).pack(anchor=tk.W)
        
        # Bind para atualizar OU quando setor muda
        self.combo_setor_novo.bind("<<ComboboxSelected>>", self.on_setor_change_novo)
    
    def colar_email_novo(self):
        """Cola email da área de transferência."""
        try:
            conteudo = self.root.clipboard_get()
            self.email_text_novo.delete(1.0, tk.END)
            self.email_text_novo.insert(tk.END, conteudo)
            self.extrair_dados_novo()
        except tk.TclError:
            messagebox.showwarning("Aviso", "Não há texto na área de transferência.")
    
    def extrair_dados_novo(self):
        """Extrai dados do email colado."""
        texto = self.email_text_novo.get(1.0, tk.END)
        
        padroes = {
            "NOME": r"NOME\s*:\s*(.+?)(?:\n|$)",
            "SETOR": r"SETOR\s*:\s*(.+?)(?:\n|$)",
            "CARGO": r"CARGO\s*:\s*(.+?)(?:\n|$)",
            "CPF": r"CPF\s*:\s*(.+?)(?:\n|$)",
            "TELEFONE": r"(?:TELEFONE|FONE|CELULAR)\s*:\s*(.+?)(?:\n|$)"
        }
        
        dados = {}
        for campo, padrao in padroes.items():
            match = re.search(padrao, texto, re.IGNORECASE)
            if match:
                dados[campo] = match.group(1).strip()
        
        # Preencher campos
        if dados.get("NOME"):
            self.entry_nome_novo.delete(0, tk.END)
            self.entry_nome_novo.insert(0, dados["NOME"])
            
            # Gerar login (primeiro.ultimo)
            partes = dados["NOME"].split()
            if len(partes) >= 2:
                primeiro = self.normalizar_texto(partes[0])
                ultimo = self.normalizar_texto(partes[-1])
                login = f"{primeiro}.{ultimo}"
            else:
                login = self.normalizar_texto(partes[0])
            
            self.entry_login_novo.delete(0, tk.END)
            self.entry_login_novo.insert(0, login)
            
            # Atualizar email exibido
            self.label_email_novo.config(text=f"{login}@guaiba.rs.gov.br")
        
        if dados.get("CARGO"):
            self.entry_cargo_novo.delete(0, tk.END)
            self.entry_cargo_novo.insert(0, dados["CARGO"])
        
        if dados.get("CPF"):
            self.entry_cpf_novo.delete(0, tk.END)
            self.entry_cpf_novo.insert(0, dados["CPF"])
        
        if dados.get("TELEFONE"):
            self.entry_telefone_novo.delete(0, tk.END)
            self.entry_telefone_novo.insert(0, dados["TELEFONE"])
        
        if dados.get("SETOR"):
            # Tentar encontrar setor correspondente
            setor = dados["SETOR"]
            for s in self.config.get("ous", {}).keys():
                if s.lower() in setor.lower() or setor.lower() in s.lower():
                    self.combo_setor_novo.set(s)
                    self.on_setor_change_novo()
                    break
        
        self.console_print("✅ Dados extraídos do email. Clique em 'Verificar' para continuar.\n")
    
    def on_setor_change_novo(self, event=None):
        """Atualiza OU quando setor muda."""
        setor = self.combo_setor_novo.get()
        ou = self.config.get("ous", {}).get(setor, "")
        self.label_ou_destino.config(text=ou if ou else "(OU não encontrada)")
    
    def verificar_usuario_novo(self):
        """Verifica se usuário existe no AD."""
        nome = self.entry_nome_novo.get().strip()
        login = self.entry_login_novo.get().strip()
        
        if not nome or not login:
            messagebox.showwarning("Aviso", "Preencha o nome e login primeiro.")
            return
        
        self.verificacao_result.config(state=tk.NORMAL)
        self.verificacao_result.delete(1.0, tk.END)
        self.verificacao_result.insert(tk.END, "🔍 Verificando...\n")
        self.verificacao_result.config(state=tk.DISABLED)
        self.root.update()
        
        script_path = self.base_dir / "scripts" / "verify_user.ps1"
        
        try:
            cmd = [
                "powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                "-Login", login,
                "-NomeCompleto", nome
            ]
            
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            self.verificacao_result.config(state=tk.NORMAL)
            self.verificacao_result.delete(1.0, tk.END)
            
            if resultado.stdout:
                try:
                    resposta = json.loads(resultado.stdout.strip())
                    
                    for msg in resposta.get("mensagens", []):
                        self.verificacao_result.insert(tk.END, f"{msg}\n")
                    
                    usuario_existe = resposta.get("usuario_existe", False)
                    usuario_desativado = resposta.get("usuario_desativado", False)
                    similares = resposta.get("usuarios_similares", [])
                    
                    if usuario_existe:
                        if usuario_desativado:
                            self.status_verificacao.config(
                                text="⚠️ Status: USUÁRIO EXISTE (DESATIVADO)",
                                foreground="orange"
                            )
                        else:
                            self.status_verificacao.config(
                                text="❌ Status: USUÁRIO JÁ EXISTE (ATIVO)",
                                foreground="red"
                            )
                        self.btn_criar_novo.config(state=tk.DISABLED)
                    elif similares:
                        self.status_verificacao.config(
                            text=f"⚠️ Status: {len(similares)} USUÁRIOS SIMILARES ENCONTRADOS",
                            foreground="orange"
                        )
                        self.btn_criar_novo.config(state=tk.NORMAL)
                    else:
                        self.status_verificacao.config(
                            text="✅ Status: PODE CRIAR - Login disponível!",
                            foreground="green"
                        )
                        self.btn_criar_novo.config(state=tk.NORMAL)
                    
                    self.log_evento("VERIFICAR_USUARIO", f"Verificação: {login}", {
                        "existe": usuario_existe,
                        "desativado": usuario_desativado,
                        "similares": len(similares)
                    })
                    
                except json.JSONDecodeError:
                    self.verificacao_result.insert(tk.END, resultado.stdout)
            else:
                self.verificacao_result.insert(tk.END, "Erro na verificação.\n")
                if resultado.stderr:
                    self.verificacao_result.insert(tk.END, resultado.stderr)
            
            self.verificacao_result.config(state=tk.DISABLED)
            
        except Exception as e:
            self.verificacao_result.config(state=tk.NORMAL)
            self.verificacao_result.delete(1.0, tk.END)
            self.verificacao_result.insert(tk.END, f"Erro: {e}")
            self.verificacao_result.config(state=tk.DISABLED)
            
    def copiar_comando_verificacao(self):
        """Gera e copia o comando de verificação para executar manualmente no servidor."""
        nome = self.entry_nome_novo.get().strip()
        login = self.entry_login_novo.get().strip()
        
        if not login:
            messagebox.showwarning("Aviso", "Preencha o login primeiro.")
            return
        
        # Gerar comando PowerShell de verificação
        cmd = f'''# Comando de Verificação de Usuário AD
# Execute no PowerShell do servidor como Admin

$login = "{login}"
$nome = "{nome}"

Write-Host "=== VERIFICANDO USUARIO ===" -ForegroundColor Cyan
Write-Host "Login: $login"
Write-Host "Nome: $nome"
Write-Host ""

# 1. Verificar se login existe
$user = Get-ADUser -Filter "SamAccountName -eq '$login'" -Properties Enabled,DisplayName -ErrorAction SilentlyContinue
if ($user) {{
    if ($user.Enabled) {{
        Write-Host "[ERRO] Usuario '$login' JA EXISTE e esta ATIVO!" -ForegroundColor Red
    }} else {{
        Write-Host "[AVISO] Usuario '$login' existe mas esta DESATIVADO" -ForegroundColor Yellow
    }}
    Write-Host "Nome atual: $($user.DisplayName)"
}} else {{
    Write-Host "[OK] Login '$login' esta DISPONIVEL!" -ForegroundColor Green
}}

# 2. Buscar usuarios similares pelo nome
Write-Host ""
Write-Host "=== USUARIOS SIMILARES ===" -ForegroundColor Cyan
$primeiroNome = ($nome -split " ")[0]
$similares = Get-ADUser -Filter "Name -like '*$primeiroNome*' -or DisplayName -like '*$primeiroNome*'" -Properties DisplayName,Enabled | Select-Object SamAccountName,DisplayName,Enabled
if ($similares) {{
    $similares | Format-Table -AutoSize
}} else {{
    Write-Host "Nenhum usuario similar encontrado."
}}
'''
        
        # Copiar para área de transferência
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        
        # Atualizar área de resultado
        self.verificacao_result.config(state=tk.NORMAL)
        self.verificacao_result.delete(1.0, tk.END)
        self.verificacao_result.insert(tk.END, "📋 COMANDO COPIADO!\n\n")
        self.verificacao_result.insert(tk.END, "Agora:\n")
        self.verificacao_result.insert(tk.END, "1. Conecte no servidor via RDP\n")
        self.verificacao_result.insert(tk.END, "2. Abra PowerShell como Admin\n")
        self.verificacao_result.insert(tk.END, "3. Cole (Ctrl+V) e execute\n")
        self.verificacao_result.insert(tk.END, f"\nVerificando: {login}\n")
        self.verificacao_result.config(state=tk.DISABLED)
        
        # Habilitar botão criar (já que não temos como verificar remotamente)
        self.btn_criar_novo.config(state=tk.NORMAL)
        self.status_verificacao.config(text="📋 Comando copiado - verifique manualmente", foreground="blue")
        
        messagebox.showinfo("Copiado!", "Comando de verificação copiado!\n\nCole no PowerShell do servidor e execute.")
            
    def verificar_usuario_remoto(self):
        """Verifica usuário remotamente via Invoke-Command (em thread separada)."""
        nome = self.entry_nome_novo.get().strip()
        login = self.entry_login_novo.get().strip()
        
        if not nome or not login:
            messagebox.showwarning("Aviso", "Preencha o nome e login primeiro.")
            return

        # Verificar se tem credencial salva
        tem_cred = self.tem_credencial_salva()
        
        self.verificacao_result.config(state=tk.NORMAL)
        self.verificacao_result.delete(1.0, tk.END)
        self.verificacao_result.insert(tk.END, "🚀 Iniciando verificação REMOTA...\n")
        
        if tem_cred:
            self.verificacao_result.insert(tk.END, "✅ Usando credenciais salvas...\n")
        else:
            self.verificacao_result.insert(tk.END, "Uma janela pedirá credenciais de ADMIN...\n")
            self.verificacao_result.insert(tk.END, "💡 Dica: Vá em Servidor > Salvar Credenciais para não pedir novamente.\n")
        
        self.verificacao_result.insert(tk.END, "Aguarde...\n")
        self.verificacao_result.config(state=tk.DISABLED)
        self.root.update()

        # Executar em thread separada para não travar a interface
        def executar_verificacao():
            script_path = self.base_dir / "scripts" / "verify_user.ps1"
            servidor = self.config.get("mremoteng", {}).get("servidor_ad", {}).get("hostname", "172.16.0.26")
            
            # Obter comando de credencial (salva ou Get-Credential)
            cred_cmd = self.get_ps_credential_cmd()
            
            ps_cmd = f"{cred_cmd}; Invoke-Command -ComputerName {servidor} -FilePath '{script_path}' -ArgumentList '{login}', '{nome}' -Credential $cred"
            
            cmd_wrapper = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd]
            
            try:
                # Não usar PIPE para stdout/stderr para mostrar a janela de credenciais
                processo = subprocess.run(
                    cmd_wrapper,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                # Atualizar interface na thread principal
                self.root.after(0, lambda: self._processar_resultado_verificacao(processo.stdout, processo.stderr))
                
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self._mostrar_erro_verificacao("Timeout - verificação demorou muito."))
            except Exception as e:
                self.root.after(0, lambda: self._mostrar_erro_verificacao(str(e)))
        
        # Iniciar thread
        thread = threading.Thread(target=executar_verificacao, daemon=True)
        thread.start()
    
    def _processar_resultado_verificacao(self, stdout, stderr):
        """Processa o resultado da verificação remota (chamado na thread principal)."""
        self.verificacao_result.config(state=tk.NORMAL)
        self.verificacao_result.delete(1.0, tk.END)
        
        if stdout:
            try:
                json_str = stdout.strip()
                idx_chave = json_str.find('{')
                if idx_chave != -1:
                    json_str = json_str[idx_chave:]
                
                resposta = json.loads(json_str)
                
                for msg in resposta.get("mensagens", []):
                    self.verificacao_result.insert(tk.END, f"{msg}\n")
                
                usuario_existe = resposta.get("usuario_existe", False)
                similares = resposta.get("usuarios_similares", [])
                
                if usuario_existe:
                    self.status_verificacao.config(text="❌ Status: USUÁRIO JÁ EXISTE", foreground="red")
                    self.btn_criar_novo.config(state=tk.DISABLED)
                elif similares:
                    self.status_verificacao.config(text=f"⚠️ Status: {len(similares)} SIMILARES", foreground="orange")
                    self.btn_criar_novo.config(state=tk.NORMAL)
                else:
                    self.status_verificacao.config(text="✅ Status: DISPONÍVEL (Remoto)", foreground="green")
                    self.btn_criar_novo.config(state=tk.NORMAL)
                    
            except json.JSONDecodeError:
                self.verificacao_result.insert(tk.END, "--- Resposta Bruta ---\n")
                self.verificacao_result.insert(tk.END, stdout)
                self.btn_criar_novo.config(state=tk.NORMAL)
        else:
            self.verificacao_result.insert(tk.END, "Erro na verificação remota (sem saída).\n")
            if stderr:
                self.verificacao_result.insert(tk.END, stderr)
        
        self.verificacao_result.config(state=tk.DISABLED)
    
    def _mostrar_erro_verificacao(self, erro):
        """Mostra erro de verificação (chamado na thread principal)."""
        self.verificacao_result.config(state=tk.NORMAL)
        self.verificacao_result.delete(1.0, tk.END)
        self.verificacao_result.insert(tk.END, f"Erro crítico: {erro}")
        self.verificacao_result.config(state=tk.DISABLED)
    
    def criar_usuario_novo(self):
        """Gera o comando PowerShell para criar usuário no servidor."""
        nome = self.entry_nome_novo.get().strip()
        login = self.entry_login_novo.get().strip()
        setor = self.combo_setor_novo.get()
        cargo = self.entry_cargo_novo.get().strip()
        cpf = self.entry_cpf_novo.get().strip()
        telefone = self.entry_telefone_novo.get().strip()
        
        if not all([nome, login, setor, cargo]):
            messagebox.showerror("Erro", "Preencha todos os campos obrigatórios (Nome, Login, Setor, Cargo).")
            return
        
        ou = self.config.get("ous", {}).get(setor, "")
        if not ou:
            messagebox.showerror("Erro", "OU não encontrada para o setor.")
            return
        
        # Gerar senha
        senha = self.gerar_senha()
        
        # Obter grupos
        grupos_padrao = self.config.get("grupos_padrao", [])
        grupos_setor = self.config.get("grupos_por_setor", {}).get(setor, [])
        grupos = grupos_padrao + grupos_setor
        
        # Email gerado
        email = f"{login}@guaiba.rs.gov.br"
        
        # Separar primeiro nome e sobrenome
        partes = nome.split()
        primeiro_nome = partes[0]
        sobrenome = " ".join(partes[1:]) if len(partes) > 1 else ""
        
        # Gerar comando PowerShell para executar NO SERVIDOR
        cmd_ps = f'''# ============================================
# COMANDO PARA CRIAR USUARIO NO AD
# Execute este comando no servidor como Admin
# ============================================

# Dados do usuario
$Nome = "{nome}"
$Login = "{login}"
$Senha = ConvertTo-SecureString -String "{senha}" -AsPlainText -Force
$OU = "{ou}"

# Criar usuario
New-ADUser `
    -Name "{nome}" `
    -GivenName "{primeiro_nome}" `
    -Surname "{sobrenome}" `
    -SamAccountName "{login}" `
    -UserPrincipalName "{email}" `
    -DisplayName "{nome}" `
    -EmailAddress "{email}" `
    -Description "{cpf}" `
    -Office "{cargo}" `
    -Title "{cargo}" `
    -Department "{setor}" `
    -OfficePhone "{telefone}" `
    -Path "{ou}" `
    -AccountPassword $Senha `
    -Enabled $true `
    -ChangePasswordAtLogon $true

# Adicionar aos grupos
{chr(10).join([f'Add-ADGroupMember -Identity "{g}" -Members "{login}"' for g in grupos])}

Write-Host "Usuario {login} criado com sucesso!"
Write-Host "Senha: {senha}"
'''
        
        # Mostrar resultado
        self.resultado_criacao.delete(1.0, tk.END)
        self.resultado_criacao.insert(tk.END, f"COMANDO GERADO - COPIE E COLE NO SERVIDOR:\n\n")
        self.resultado_criacao.insert(tk.END, cmd_ps)
        
        # Copiar para area de transferencia
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd_ps)
        
        # Mostrar resumo
        self.console_print(f"\n{'='*60}\n")
        self.console_print(f"COMANDO GERADO PARA CRIAR USUARIO\n")
        self.console_print(f"{'='*60}\n")
        self.console_print(f"Login: {login}\n")
        self.console_print(f"Email: {email}\n")
        self.console_print(f"Senha: {senha}\n")
        self.console_print(f"OU: {ou}\n")
        self.console_print(f"\nCOMANDO COPIADO PARA A AREA DE TRANSFERENCIA!\n")
        self.console_print(f"Cole no PowerShell do servidor (Admin) e execute.\n")
        
        # Log
        self.log_evento("GERAR_COMANDO_USUARIO", f"Comando gerado para {login}", {
            "login": login, "nome": nome, "setor": setor, "email": email
        })
        
        # Avisar usuario
        messagebox.showinfo(
            "Comando Gerado!",
            f"O comando PowerShell foi COPIADO para a area de transferencia!\n\n"
            f"Login: {login}\n"
            f"Senha: {senha}\n\n"
            f"Agora:\n"
            f"1. Conecte ao servidor via RDP\n"
            f"2. Abra o PowerShell como Administrador\n"
            f"3. Cole (Ctrl+V) e execute o comando\n\n"
            f"OU clique em 'Executar no Servidor' para tentar automação remota."
        )
        
    def executar_comando_remoto(self):
        """Executa o comando gerado remotamente no servidor via Invoke-Command (em thread separada)."""
        # Verificar se tem comando na área de transferência
        try:
            cmd_ps = self.root.clipboard_get()
            if "New-ADUser" not in cmd_ps:
                messagebox.showwarning("Aviso", "Gere o comando primeiro (clique em CRIAR USUÁRIO).")
                return
        except:
            messagebox.showwarning("Aviso", "Nada na área de transferência.")
            return

        # Configurações do servidor
        servidor = self.config.get("mremoteng", {}).get("servidor_ad", {}).get("hostname", "172.16.0.26")
        
        # Salvar script temporário
        script_file = self.base_dir / "temp_remote_script.ps1"
        with open(script_file, "w") as f:
            f.write(cmd_ps)
        
        tem_cred = self.tem_credencial_salva()
        
        self.console_print(f"\n{'='*60}\n")
        self.console_print(f"🚀 INICIANDO EXECUÇÃO REMOTA EM: {servidor}\n")
        self.console_print(f"{'='*60}\n")
        
        if tem_cred:
            self.console_print("✅ Usando credenciais salvas...\n")
        else:
            self.console_print("Uma janela pedirá as credenciais de ADMIN...\n")
        
        self.console_print("Aguarde...\n")
        
        # Executar em thread separada
        def executar_remoto():
            cred_cmd = self.get_ps_credential_cmd()
            ps_cmd = f"{cred_cmd}; Invoke-Command -ComputerName {servidor} -FilePath '{script_file}' -Credential $cred"
            
            cmd_wrapper = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd]
            
            try:
                processo = subprocess.run(
                    cmd_wrapper,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                self.root.after(0, lambda: self._processar_resultado_criacao(processo.stdout, processo.stderr, processo.returncode, servidor))
                
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self._mostrar_erro_criacao("Timeout - comando demorou muito."))
            except Exception as e:
                self.root.after(0, lambda: self._mostrar_erro_criacao(str(e)))
        
        thread = threading.Thread(target=executar_remoto, daemon=True)
        thread.start()
    
    def _processar_resultado_criacao(self, stdout, stderr, returncode, servidor):
        """Processa resultado da criação remota (thread principal)."""
        self.console_print(f"\n--- SAÍDA DO SERVIDOR ---\n")
        if stdout:
            self.console_print(stdout)
        
        if stderr:
            self.console_print(f"\n--- ERROS/AVISOS ---\n")
            self.console_print(stderr)
            
        if returncode == 0:
            messagebox.showinfo("Sucesso", "Comando executado remotamente com sucesso!")
            self.log_evento("EXECUCAO_REMOTA", f"Script executado em {servidor}", {"status": "sucesso"})
        else:
            messagebox.showerror("Erro", "Falha na execução remota. Verifique o console.")
            self.log_evento("EXECUCAO_REMOTA", f"Falha em {servidor}", {"status": "erro", "erro": stderr})
    
    def _mostrar_erro_criacao(self, erro):
        """Mostra erro de criação (thread principal)."""
        self.console_print(f"Erro crítico: {erro}\n")
        messagebox.showerror("Erro", f"Erro ao tentar executar: {erro}")
    
    def copiar_resultado_novo(self):
        """Copia resultado para área de transferência."""
        texto = self.resultado_criacao.get(1.0, tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(texto)
        messagebox.showinfo("Copiado", "Resultado copiado!")

    def create_email_tab(self):
        """Cria a aba de importação de email."""
        # Instruções
        instrucoes = ttk.Label(
            self.tab_email,
            text="Cole o texto do email de solicitação abaixo. O sistema irá extrair automaticamente os dados.",
            font=("Segoe UI", 10),
            wraplength=800
        )
        instrucoes.pack(anchor=tk.W, pady=5)
        
        # Formato esperado
        formato_frame = ttk.LabelFrame(self.tab_email, text="Formato esperado", padding="5")
        formato_frame.pack(fill=tk.X, pady=5)
        
        formato_texto = """NOME: João da Silva Santos
CPF: 123.456.789-00
TELEFONE: (51) 99999-9999
SECRETARIA: Secretaria de Educação
SETOR: Educação
CARGO: Técnico Administrativo"""
        
        ttk.Label(
            formato_frame,
            text=formato_texto,
            font=("Consolas", 9),
            foreground="gray"
        ).pack(anchor=tk.W)
        
        # Área de texto para colar email
        email_frame = ttk.LabelFrame(self.tab_email, text="Conteúdo do Email", padding="10")
        email_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.email_text = scrolledtext.ScrolledText(
            email_frame,
            height=10,
            font=("Consolas", 10)
        )
        self.email_text.pack(fill=tk.BOTH, expand=True)
        
        # Botões
        btn_frame = ttk.Frame(self.tab_email)
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            btn_frame,
            text="📋 Colar da Área de Transferência",
            command=self.colar_email
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="🔍 Extrair Dados",
            command=self.extrair_dados_email
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="🧹 Limpar",
            command=lambda: self.email_text.delete(1.0, tk.END)
        ).pack(side=tk.LEFT, padx=5)
        
        # Preview dos dados extraídos
        preview_frame = ttk.LabelFrame(self.tab_email, text="Dados Extraídos (Preview)", padding="10")
        preview_frame.pack(fill=tk.X, pady=5)
        
        # Labels para preview
        self.preview_labels = {}
        campos = ["NOME", "CPF", "TELEFONE", "SECRETARIA", "SETOR", "CARGO"]
        
        for i, campo in enumerate(campos):
            ttk.Label(preview_frame, text=f"{campo}:").grid(row=i, column=0, sticky=tk.W, pady=2)
            label = ttk.Label(preview_frame, text="-", font=("Segoe UI", 10, "bold"))
            label.grid(row=i, column=1, sticky=tk.W, pady=2, padx=10)
            self.preview_labels[campo] = label
        
        # Botão para ir para criação
        ttk.Button(
            preview_frame,
            text="✅ Confirmar e Ir para Criação de Usuário",
            command=self.confirmar_e_criar
        ).grid(row=len(campos), column=0, columnspan=2, pady=10)
    
    def colar_email(self):
        """Cola o conteúdo da área de transferência no campo de email."""
        try:
            conteudo = self.root.clipboard_get()
            self.email_text.delete(1.0, tk.END)
            self.email_text.insert(tk.END, conteudo)
            self.extrair_dados_email()
        except tk.TclError:
            messagebox.showwarning("Aviso", "Não há texto na área de transferência.")
    
    def extrair_dados_email(self):
        """Extrai dados do email colado."""
        texto = self.email_text.get(1.0, tk.END)
        
        # Padrões de extração
        padroes = {
            "NOME": r"NOME\s*:\s*(.+?)(?:\n|$)",
            "CPF": r"CPF\s*:\s*(.+?)(?:\n|$)",
            "TELEFONE": r"TELEFONE\s*:\s*(.+?)(?:\n|$)",
            "SECRETARIA": r"SECRETARIA\s*:\s*(.+?)(?:\n|$)",
            "SETOR": r"SETOR\s*:\s*(.+?)(?:\n|$)",
            "CARGO": r"CARGO\s*:\s*(.+?)(?:\n|$)"
        }
        
        self.dados_extraidos = {}
        
        for campo, padrao in padroes.items():
            match = re.search(padrao, texto, re.IGNORECASE)
            if match:
                valor = match.group(1).strip()
                self.dados_extraidos[campo] = valor
                self.preview_labels[campo].config(text=valor, foreground="green")
            else:
                self.dados_extraidos[campo] = ""
                self.preview_labels[campo].config(text="(não encontrado)", foreground="red")
        
        # Verificar se encontrou os dados essenciais
        if self.dados_extraidos.get("NOME") and self.dados_extraidos.get("SETOR"):
            self.console_print(f"✅ Dados extraídos com sucesso do email.\n")
            self.log_evento("EXTRAIR_EMAIL", "Dados extraídos do email", self.dados_extraidos)
        else:
            self.console_print("⚠️ Alguns campos obrigatórios não foram encontrados.\n")
    
    def confirmar_e_criar(self):
        """Confirma os dados e vai para a aba de criação."""
        if not hasattr(self, 'dados_extraidos') or not self.dados_extraidos.get("NOME"):
            messagebox.showwarning("Aviso", "Extraia os dados do email primeiro.")
            return
        
        # Preencher formulário de criação
        self.entry_nome.delete(0, tk.END)
        self.entry_nome.insert(0, self.dados_extraidos.get("NOME", ""))
        
        self.entry_cargo.delete(0, tk.END)
        self.entry_cargo.insert(0, self.dados_extraidos.get("CARGO", ""))
        
        # Tentar selecionar o setor
        setor = self.dados_extraidos.get("SETOR", "")
        setores_disponiveis = list(self.config.get("ous", {}).keys())
        
        # Tentar encontrar correspondência
        setor_encontrado = None
        for s in setores_disponiveis:
            if s.lower() in setor.lower() or setor.lower() in s.lower():
                setor_encontrado = s
                break
        
        if setor_encontrado:
            self.combo_setor.set(setor_encontrado)
            self.on_setor_change()
        else:
            self.console_print(f"⚠️ Setor '{setor}' não encontrado nas OUs configuradas.\n")
        
        # Gerar login
        self.gerar_login()
        
        # Ir para aba de criação
        self.notebook.select(self.tab_usuario)
        
        self.console_print(f"📝 Formulário preenchido com dados do email. Confira e clique em 'Criar Usuário'.\n")

    def create_user_tab(self):
        """Cria a aba de criação de usuários."""
        # Frame do formulário
        form_frame = ttk.LabelFrame(self.tab_usuario, text="Dados do Novo Usuário", padding="10")
        form_frame.pack(fill=tk.X, pady=5)
        
        # Nome completo
        ttk.Label(form_frame, text="Nome Completo:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.entry_nome = ttk.Entry(form_frame, width=50)
        self.entry_nome.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=3, padx=5)
        
        # Setor
        ttk.Label(form_frame, text="Setor:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.combo_setor = ttk.Combobox(
            form_frame, 
            values=list(self.config.get("ous", {}).keys()),
            state="readonly",
            width=30
        )
        self.combo_setor.grid(row=1, column=1, sticky=tk.W, pady=3, padx=5)
        self.combo_setor.bind("<<ComboboxSelected>>", self.on_setor_change)
        
        # Cargo
        ttk.Label(form_frame, text="Cargo:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.entry_cargo = ttk.Entry(form_frame, width=50)
        self.entry_cargo.grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=3, padx=5)
        
        # Login gerado
        ttk.Label(form_frame, text="Login (gerado):").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.entry_login = ttk.Entry(form_frame, width=30, state="readonly")
        self.entry_login.grid(row=3, column=1, sticky=tk.W, pady=3, padx=5)
        
        ttk.Button(
            form_frame, 
            text="🔄 Gerar Login",
            command=self.gerar_login
        ).grid(row=3, column=2, padx=5)
        
        # Frame de grupos
        grupos_frame = ttk.LabelFrame(self.tab_usuario, text="Grupos de Acesso", padding="10")
        grupos_frame.pack(fill=tk.X, pady=5)
        
        # Grupos padrão
        self.grupos_vars = {}
        
        ttk.Label(grupos_frame, text="Grupos padrão do sistema:").pack(anchor=tk.W)
        self.grupos_padrao_frame = ttk.Frame(grupos_frame)
        self.grupos_padrao_frame.pack(fill=tk.X, pady=5)
        
        for grupo in self.config.get("grupos_padrao", []):
            var = tk.BooleanVar(value=True)
            self.grupos_vars[grupo] = var
            ttk.Checkbutton(
                self.grupos_padrao_frame,
                text=grupo,
                variable=var
            ).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(grupos_frame, text="Grupos do setor (selecionado):").pack(anchor=tk.W, pady=(10, 0))
        self.grupos_setor_frame = ttk.Frame(grupos_frame)
        self.grupos_setor_frame.pack(fill=tk.X, pady=5)
        
        # Botões de ação
        btn_frame = ttk.Frame(self.tab_usuario)
        btn_frame.pack(fill=tk.X, pady=10)
        
        # Botão principal: Verificar + Criar (fluxo integrado)
        self.btn_criar = ttk.Button(
            btn_frame,
            text="🔍 Verificar e Criar Usuário",
            command=self.criar_usuario,
            style="Accent.TButton"
        )
        self.btn_criar.pack(side=tk.LEFT, padx=5)
        
        # Botão apenas verificar (sem criar)
        self.btn_verificar = ttk.Button(
            btn_frame,
            text="🔎 Apenas Verificar",
            command=self.verificar_usuario_existente
        )
        self.btn_verificar.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_frame,
            text="🧹 Limpar Formulário",
            command=self.limpar_formulario_usuario
        ).pack(side=tk.LEFT, padx=5)
        
        # Resultado
        result_frame = ttk.LabelFrame(self.tab_usuario, text="Resultado", padding="10")
        result_frame.pack(fill=tk.X, pady=5)
        
        self.resultado_text = scrolledtext.ScrolledText(result_frame, height=5, font=("Consolas", 10))
        self.resultado_text.pack(fill=tk.X)
        
        ttk.Button(
            result_frame,
            text="📋 Copiar Relatório",
            command=self.copiar_relatorio
        ).pack(anchor=tk.W, pady=5)
        
        # Vincular evento de nome para gerar login automaticamente
        self.entry_nome.bind("<FocusOut>", lambda e: self.gerar_login())
    
    def create_scripts_tab(self):
        """Cria a aba de execução de scripts."""
        # Seleção de script
        select_frame = ttk.LabelFrame(self.tab_scripts, text="Selecionar Script", padding="10")
        select_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(select_frame, text="Script:").pack(anchor=tk.W)
        
        # Lista de scripts disponíveis
        self.scripts_disponiveis = self.carregar_scripts_disponiveis()
        
        self.combo_script = ttk.Combobox(
            select_frame,
            values=[s["nome"] for s in self.scripts_disponiveis],
            state="readonly",
            width=60
        )
        self.combo_script.pack(fill=tk.X, pady=5)
        self.combo_script.bind("<<ComboboxSelected>>", self.on_script_change)
        
        # Descrição do script
        self.script_desc_label = ttk.Label(
            select_frame, 
            text="Selecione um script para ver a descrição.",
            wraplength=600
        )
        self.script_desc_label.pack(anchor=tk.W, pady=5)
        
        # Frame de parâmetros
        self.params_frame = ttk.LabelFrame(self.tab_scripts, text="Parâmetros", padding="10")
        self.params_frame.pack(fill=tk.X, pady=5)
        
        self.param_entries = {}
        
        # Botão executar
        btn_frame = ttk.Frame(self.tab_scripts)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.btn_executar = ttk.Button(
            btn_frame,
            text="▶️ Executar Script",
            command=self.executar_script
        )
        self.btn_executar.pack(side=tk.LEFT, padx=5)
    
    def create_servidor_tab(self):
        """Cria a aba de conexão com o servidor."""
        # Título
        titulo = ttk.Label(
            self.tab_servidor,
            text="Conectar ao Servidor AD via mRemoteNG",
            font=("Segoe UI", 12, "bold")
        )
        titulo.pack(anchor=tk.W, pady=10)
        
        # Informações do servidor
        info_frame = ttk.LabelFrame(self.tab_servidor, text="Configuração do Servidor", padding="15")
        info_frame.pack(fill=tk.X, pady=10)
        
        # Carregar configuração do mRemoteNG
        mremoteng_config = self.config.get("mremoteng", {})
        servidor_config = mremoteng_config.get("servidor_ad", {})
        
        # Campos de configuração
        ttk.Label(info_frame, text="Caminho do mRemoteNG:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.entry_mremoteng_path = ttk.Entry(info_frame, width=60)
        self.entry_mremoteng_path.insert(0, mremoteng_config.get("caminho_executavel", "C:\\Program Files (x86)\\mRemoteNG\\mRemoteNG.exe"))
        self.entry_mremoteng_path.grid(row=0, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Button(
            info_frame,
            text="📂 Procurar",
            command=self.procurar_mremoteng
        ).grid(row=0, column=2, padx=5)
        
        ttk.Label(info_frame, text="Nome do Servidor:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.entry_servidor_nome = ttk.Entry(info_frame, width=40)
        self.entry_servidor_nome.insert(0, servidor_config.get("nome", "Servidor AD"))
        self.entry_servidor_nome.grid(row=1, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(info_frame, text="Hostname/IP:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.entry_servidor_host = ttk.Entry(info_frame, width=40)
        self.entry_servidor_host.insert(0, servidor_config.get("hostname", "dc01.guaiba.local"))
        self.entry_servidor_host.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        
        ttk.Label(info_frame, text="Usuário (opcional):").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.entry_servidor_user = ttk.Entry(info_frame, width=40)
        self.entry_servidor_user.insert(0, servidor_config.get("usuario", ""))
        self.entry_servidor_user.grid(row=3, column=1, sticky=tk.W, pady=5, padx=5)
        
        # Frame de ações
        acoes_frame = ttk.LabelFrame(self.tab_servidor, text="Ações", padding="15")
        acoes_frame.pack(fill=tk.X, pady=10)
        
        # Botão para conectar via mRemoteNG
        btn_mremoteng = ttk.Button(
            acoes_frame,
            text="🖥️ Abrir mRemoteNG",
            command=self.abrir_mremoteng
        )
        btn_mremoteng.pack(side=tk.LEFT, padx=5, pady=10)
        
        # Botão para conectar direto via RDP (mstsc)
        btn_rdp = ttk.Button(
            acoes_frame,
            text="🔗 Conectar via RDP (mstsc)",
            command=self.conectar_rdp_direto
        )
        btn_rdp.pack(side=tk.LEFT, padx=5, pady=10)
        
        # Botão para salvar configuração
        btn_salvar = ttk.Button(
            acoes_frame,
            text="💾 Salvar Configuração",
            command=self.salvar_config_servidor
        )
        btn_salvar.pack(side=tk.LEFT, padx=5, pady=10)
        
        # Frame de credenciais
        cred_frame = ttk.LabelFrame(self.tab_servidor, text="🔑 Credenciais de Admin (Execução Remota)", padding="15")
        cred_frame.pack(fill=tk.X, pady=10)
        
        # Info sobre credenciais
        cred_info = ttk.Label(
            cred_frame,
            text="Salve suas credenciais de admin para não precisar digitar a senha toda vez.\nAs credenciais são criptografadas e só funcionam no seu usuário Windows.",
            justify=tk.LEFT
        )
        cred_info.pack(anchor=tk.W, pady=5)
        
        # Status da credencial
        self.lbl_cred_status = ttk.Label(
            cred_frame,
            text="",
            font=("Segoe UI", 10)
        )
        self.lbl_cred_status.pack(anchor=tk.W, pady=5)
        self.atualizar_status_credencial()
        
        # Botões de credencial
        btn_cred_frame = ttk.Frame(cred_frame)
        btn_cred_frame.pack(anchor=tk.W, pady=5)
        
        ttk.Button(
            btn_cred_frame,
            text="💾 Salvar Credenciais",
            command=self.salvar_e_atualizar_credencial
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            btn_cred_frame,
            text="🗑️ Remover Credenciais",
            command=self.remover_e_atualizar_credencial
        ).pack(side=tk.LEFT, padx=5)
        
        # Instruções
        instrucoes_frame = ttk.LabelFrame(self.tab_servidor, text="Instruções", padding="10")
        instrucoes_frame.pack(fill=tk.X, pady=10)
        
        instrucoes_texto = """
1. Configure o caminho do mRemoteNG se não estiver no local padrão
2. Informe o hostname ou IP do servidor AD
3. Clique em "Abrir mRemoteNG" para iniciar o programa
4. Ou use "Conectar via RDP" para abrir conexão direta

⚠️ NOTA: Após conectar ao servidor, execute os scripts PowerShell diretamente no servidor.
O aplicativo irá copiar o comando necessário para a área de transferência.
        """
        
        ttk.Label(
            instrucoes_frame,
            text=instrucoes_texto.strip(),
            justify=tk.LEFT,
            wraplength=700
        ).pack(anchor=tk.W)
        
        # Frame para comando a copiar
        cmd_frame = ttk.LabelFrame(self.tab_servidor, text="Comando para Executar no Servidor", padding="10")
        cmd_frame.pack(fill=tk.X, pady=10)
        
        self.servidor_cmd_text = scrolledtext.ScrolledText(cmd_frame, height=4, font=("Consolas", 10))
        self.servidor_cmd_text.pack(fill=tk.X)
        self.servidor_cmd_text.insert(tk.END, "# O comando será gerado quando você criar um usuário")
        
        ttk.Button(
            cmd_frame,
            text="📋 Copiar Comando",
            command=self.copiar_comando_servidor
        ).pack(anchor=tk.W, pady=5)
    
    def procurar_mremoteng(self):
        """Abre diálogo para selecionar o executável do mRemoteNG."""
        from tkinter import filedialog
        arquivo = filedialog.askopenfilename(
            title="Selecionar mRemoteNG",
            filetypes=[("Executável", "*.exe"), ("Todos os arquivos", "*.*")],
            initialdir="C:\\Program Files (x86)"
        )
        if arquivo:
            self.entry_mremoteng_path.delete(0, tk.END)
            self.entry_mremoteng_path.insert(0, arquivo)
    
    def abrir_mremoteng(self):
        """Abre o mRemoteNG."""
        caminho = self.entry_mremoteng_path.get().strip()
        
        if not caminho or not Path(caminho).exists():
            messagebox.showerror("Erro", f"mRemoteNG não encontrado em: {caminho}\n\nVerifique o caminho do executável.")
            return
        
        try:
            subprocess.Popen([caminho], shell=False)
            self.console_print(f"✅ mRemoteNG iniciado: {caminho}\n")
            self.log_evento("ABRIR_MREMOTENG", f"mRemoteNG aberto: {caminho}")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao abrir mRemoteNG: {e}")
            self.console_print(f"❌ Erro ao abrir mRemoteNG: {e}\n")
    
    def conectar_rdp_direto(self):
        """Conecta diretamente via RDP usando mstsc."""
        hostname = self.entry_servidor_host.get().strip()
        usuario = self.entry_servidor_user.get().strip()
        
        if not hostname:
            messagebox.showerror("Erro", "Informe o hostname ou IP do servidor.")
            return
        
        try:
            cmd = ["mstsc", f"/v:{hostname}"]
            if usuario:
                # Criar arquivo .rdp temporário com usuário
                rdp_content = f"""full address:s:{hostname}
username:s:{usuario}
prompt for credentials:i:1
"""
                rdp_file = self.base_dir / "temp_connection.rdp"
                with open(rdp_file, 'w') as f:
                    f.write(rdp_content)
                cmd = ["mstsc", str(rdp_file)]
            
            subprocess.Popen(cmd, shell=False)
            self.console_print(f"✅ Conexão RDP iniciada para: {hostname}\n")
            self.log_evento("CONECTAR_RDP", f"Conexão RDP para {hostname}", {"usuario": usuario})
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao conectar via RDP: {e}")
            self.console_print(f"❌ Erro na conexão RDP: {e}\n")
    
    def salvar_config_servidor(self):
        """Salva a configuração do servidor no arquivo settings.json."""
        config_path = self.base_dir / "config" / "settings.json"
        
        # Atualizar config
        self.config["mremoteng"] = {
            "caminho_executavel": self.entry_mremoteng_path.get().strip(),
            "servidor_ad": {
                "nome": self.entry_servidor_nome.get().strip(),
                "hostname": self.entry_servidor_host.get().strip(),
                "usuario": self.entry_servidor_user.get().strip(),
                "protocolo": "RDP"
            }
        }
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Sucesso", "Configuração salva com sucesso!")
            self.console_print("✅ Configuração do servidor salva.\n")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao salvar configuração: {e}")
    
    def copiar_comando_servidor(self):
        """Copia o comando para executar no servidor."""
        comando = self.servidor_cmd_text.get(1.0, tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(comando)
        messagebox.showinfo("Copiado", "Comando copiado para a área de transferência.")
    
    def atualizar_comando_servidor(self, nome, login, setor, cargo, senha, ou, grupos):
        """Atualiza o comando a ser executado no servidor."""
        grupos_str = ",".join(grupos) if grupos else ""
        
        comando = f'''# Executar no PowerShell do Servidor AD
Import-Module ActiveDirectory

$senha = ConvertTo-SecureString -String "{senha}" -AsPlainText -Force

New-ADUser `
    -Name "{nome}" `
    -SamAccountName "{login}" `
    -UserPrincipalName "{login}@GUAIBA.LOCAL" `
    -GivenName "{nome.split()[0]}" `
    -Surname "{nome.split()[-1] if len(nome.split()) > 1 else ''}" `
    -DisplayName "{nome}" `
    -Description "{cargo}" `
    -Title "{cargo}" `
    -Department "{setor}" `
    -Path "{ou}" `
    -AccountPassword $senha `
    -Enabled $true `
    -ChangePasswordAtLogon $true

# Adicionar aos grupos
{chr(10).join([f'Add-ADGroupMember -Identity "{g}" -Members "{login}"' for g in grupos]) if grupos else '# Nenhum grupo selecionado'}

Write-Host "Usuario {login} criado com sucesso!"
'''
        
        if hasattr(self, 'servidor_cmd_text'):
            self.servidor_cmd_text.delete(1.0, tk.END)
            self.servidor_cmd_text.insert(tk.END, comando)

    def create_logs_tab(self):
        """Cria a aba de logs."""
        # Botões
        btn_frame = ttk.Frame(self.tab_logs)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(
            btn_frame,
            text="🔄 Atualizar Logs",
            command=self.carregar_logs
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame,
            text="📂 Abrir Pasta de Logs",
            command=self.abrir_pasta_logs
        ).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(
            btn_frame,
            text="📋 Copiar Logs",
            command=self.copiar_logs
        ).pack(side=tk.LEFT, padx=2)
        
        # Área de logs
        self.logs_text = scrolledtext.ScrolledText(
            self.tab_logs,
            font=("Consolas", 9),
            height=20
        )
        self.logs_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def carregar_scripts_disponiveis(self):
        """Carrega lista de scripts pré-aprovados."""
        scripts = [
            {
                "nome": "Reset de Senha",
                "arquivo": "reset_password.ps1",
                "descricao": "Reseta a senha de um usuário e força a troca no próximo login.",
                "parametros": [
                    {"nome": "Login", "label": "Login do Usuário", "obrigatorio": True},
                    {"nome": "NovaSenha", "label": "Nova Senha (deixe vazio para gerar)", "obrigatorio": False}
                ]
            },
            {
                "nome": "Desabilitar Usuário",
                "arquivo": "disable_user.ps1",
                "descricao": "Desabilita uma conta de usuário no Active Directory.",
                "parametros": [
                    {"nome": "Login", "label": "Login do Usuário", "obrigatorio": True}
                ]
            }
        ]
        return scripts
    
    def on_setor_change(self, event=None):
        """Atualiza grupos quando o setor é alterado."""
        setor = self.combo_setor.get()
        
        # Limpar grupos do setor anterior
        for widget in self.grupos_setor_frame.winfo_children():
            widget.destroy()
        
        # Adicionar grupos do novo setor
        grupos_setor = self.config.get("grupos_por_setor", {}).get(setor, [])
        for grupo in grupos_setor:
            var = tk.BooleanVar(value=True)
            self.grupos_vars[grupo] = var
            ttk.Checkbutton(
                self.grupos_setor_frame,
                text=grupo,
                variable=var
            ).pack(side=tk.LEFT, padx=5)
    
    def on_script_change(self, event=None):
        """Atualiza interface quando um script é selecionado."""
        nome_script = self.combo_script.get()
        
        # Encontrar script
        script = None
        for s in self.scripts_disponiveis:
            if s["nome"] == nome_script:
                script = s
                break
        
        if not script:
            return
        
        # Atualizar descrição
        self.script_desc_label.config(text=script["descricao"])
        
        # Limpar parâmetros anteriores
        for widget in self.params_frame.winfo_children():
            widget.destroy()
        self.param_entries.clear()
        
        # Criar campos de parâmetros
        for i, param in enumerate(script.get("parametros", [])):
            label_text = param["label"]
            if param.get("obrigatorio"):
                label_text += " *"
            
            ttk.Label(self.params_frame, text=label_text).grid(
                row=i, column=0, sticky=tk.W, pady=3
            )
            
            entry = ttk.Entry(self.params_frame, width=50)
            entry.grid(row=i, column=1, sticky=tk.W, pady=3, padx=5)
            self.param_entries[param["nome"]] = entry
    
    def normalizar_texto(self, texto):
        """Remove acentos e caracteres especiais."""
        texto = unicodedata.normalize('NFKD', texto)
        texto = ''.join(c for c in texto if not unicodedata.combining(c))
        return texto.lower()
    
    def gerar_login(self):
        """Gera login no formato nome.sobrenome."""
        nome_completo = self.entry_nome.get().strip()
        if not nome_completo:
            return
        
        partes = nome_completo.split()
        if len(partes) >= 2:
            primeiro = self.normalizar_texto(partes[0])
            ultimo = self.normalizar_texto(partes[-1])
            login = f"{primeiro}.{ultimo}"
        else:
            login = self.normalizar_texto(partes[0])
        
        # Remover caracteres inválidos
        login = ''.join(c for c in login if c.isalnum() or c == '.')
        
        self.entry_login.config(state="normal")
        self.entry_login.delete(0, tk.END)
        self.entry_login.insert(0, login)
        self.entry_login.config(state="readonly")
    
    def gerar_senha(self):
        """Gera uma senha aleatória segura."""
        config_senha = self.config.get("senha", {})
        tamanho = config_senha.get("tamanho", 12)
        
        caracteres = ""
        if config_senha.get("incluir_maiusculas", True):
            caracteres += string.ascii_uppercase
        if config_senha.get("incluir_minusculas", True):
            caracteres += string.ascii_lowercase
        if config_senha.get("incluir_numeros", True):
            caracteres += string.digits
        if config_senha.get("incluir_especiais", True):
            caracteres += "!@#$%&*"
        
        if not caracteres:
            caracteres = string.ascii_letters + string.digits
        
        # Garantir que tem pelo menos um de cada tipo
        senha = []
        if config_senha.get("incluir_maiusculas", True):
            senha.append(random.choice(string.ascii_uppercase))
        if config_senha.get("incluir_minusculas", True):
            senha.append(random.choice(string.ascii_lowercase))
        if config_senha.get("incluir_numeros", True):
            senha.append(random.choice(string.digits))
        if config_senha.get("incluir_especiais", True):
            senha.append(random.choice("!@#$%&*"))
        
        # Completar com caracteres aleatórios
        while len(senha) < tamanho:
            senha.append(random.choice(caracteres))
        
        random.shuffle(senha)
        return ''.join(senha)
    
    def verificar_ambiente(self):
        """Verifica se o ambiente está configurado corretamente."""
        self.console_print("Verificando ambiente...\n")
        
        script_path = self.base_dir / "scripts" / "check_ad_module.ps1"
        
        if not script_path.exists():
            self.status_label.config(
                text="⚠️ Script de verificação não encontrado",
                foreground="orange"
            )
            self.console_print("AVISO: Script check_ad_module.ps1 não encontrado.\n")
            return
        
        try:
            resultado = subprocess.run(
                ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if resultado.stdout:
                self.info_ambiente = json.loads(resultado.stdout.strip())
                
                # Atualizar status
                if self.info_ambiente.get("modulo_instalado") and self.info_ambiente.get("conectado_dominio"):
                    self.ambiente_ok = True
                    self.status_label.config(
                        text=f"✅ Conectado ao domínio {self.info_ambiente.get('dominio', 'N/A')} | Usuário: {self.info_ambiente.get('usuario_atual', 'N/A')}",
                        foreground="green"
                    )
                else:
                    self.status_label.config(
                        text="⚠️ Ambiente com problemas - Verifique o console",
                        foreground="orange"
                    )
                
                # Mostrar mensagens no console
                for msg in self.info_ambiente.get("mensagens", []):
                    self.console_print(f"{msg}\n")
            else:
                self.console_print(f"Erro na verificação: {resultado.stderr}\n")
                self.status_label.config(
                    text="❌ Erro ao verificar ambiente",
                    foreground="red"
                )
                
        except subprocess.TimeoutExpired:
            self.console_print("ERRO: Timeout ao verificar ambiente.\n")
            self.status_label.config(text="❌ Timeout na verificação", foreground="red")
        except Exception as e:
            self.console_print(f"ERRO: {e}\n")
            self.status_label.config(text="❌ Erro na verificação", foreground="red")
    
    def verificar_usuario_existente(self):
        """Verifica se o usuário já existe no AD antes de criar."""
        nome = self.entry_nome.get().strip()
        login = self.entry_login.get().strip()
        
        if not login:
            # Tentar gerar login
            if nome:
                self.gerar_login()
                login = self.entry_login.get().strip()
            
            if not login:
                messagebox.showwarning("Aviso", "Preencha o nome e gere o login primeiro.")
                return
        
        self.console_print(f"\n{'='*60}\n")
        self.console_print(f"🔍 Verificando usuário: {login}\n")
        self.console_print(f"   Nome: {nome}\n")
        self.console_print(f"{'='*60}\n\n")
        
        script_path = self.base_dir / "scripts" / "verify_user.ps1"
        
        if not script_path.exists():
            messagebox.showerror("Erro", "Script verify_user.ps1 não encontrado.")
            return
        
        try:
            cmd = [
                "powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
                "-Login", login,
                "-NomeCompleto", nome
            ]
            
            resultado = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if resultado.stdout:
                try:
                    resposta = json.loads(resultado.stdout.strip())
                    
                    # Mostrar mensagens no console
                    for msg in resposta.get("mensagens", []):
                        self.console_print(f"{msg}\n")
                    
                    # Atualizar área de resultado
                    resultado_texto = "\n".join(resposta.get("mensagens", []))
                    self.resultado_text.delete(1.0, tk.END)
                    self.resultado_text.insert(tk.END, resultado_texto)
                    
                    # Verificar se pode criar
                    if resposta.get("usuario_existe"):
                        if resposta.get("usuario_desativado"):
                            resp = messagebox.askyesno(
                                "Usuário Desativado",
                                f"O usuário '{login}' existe mas está DESATIVADO.\n\n"
                                "Deseja reativá-lo em vez de criar um novo?"
                            )
                            if resp:
                                self.console_print("\n⚠️ Use a aba 'Executar Scripts' para reativar o usuário.\n")
                        else:
                            messagebox.showwarning(
                                "Usuário Existe",
                                f"O usuário '{login}' já existe e está ATIVO.\n\n"
                                "Não é possível criar um usuário com este login."
                            )
                    else:
                        # Verificar se há similares
                        similares = resposta.get("usuarios_similares", [])
                        if similares:
                            nomes_similares = "\n".join([
                                f"• {s['login']} - {s['nome']} [{s['status']}]"
                                for s in similares[:5]
                            ])
                            resp = messagebox.askyesno(
                                "Usuários Similares Encontrados",
                                f"Foram encontrados {len(similares)} usuários com nomes similares:\n\n"
                                f"{nomes_similares}\n\n"
                                "Deseja continuar com a criação mesmo assim?"
                            )
                            if resp:
                                self.console_print("\n✅ Usuário pode ser criado. Clique em 'Criar Usuário no AD'.\n")
                        else:
                            messagebox.showinfo(
                                "Verificação OK",
                                f"Login '{login}' está disponível!\n\n"
                                "Nenhum usuário similar encontrado.\n"
                                "Você pode prosseguir com a criação."
                            )
                            self.console_print("\n✅ Verificação concluída. Usuário pode ser criado.\n")
                    
                    # Registrar log
                    self.log_evento("VERIFICAR_USUARIO", f"Verificação do login {login}", {
                        "login": login,
                        "existe": resposta.get("usuario_existe"),
                        "desativado": resposta.get("usuario_desativado"),
                        "similares": len(resposta.get("usuarios_similares", []))
                    })
                    
                except json.JSONDecodeError:
                    self.console_print(f"Saída: {resultado.stdout}\n")
            
            if resultado.stderr:
                self.console_print(f"Erros: {resultado.stderr}\n")
                
        except subprocess.TimeoutExpired:
            self.console_print("ERRO: Timeout ao verificar usuário.\n")
            messagebox.showerror("Erro", "Timeout ao verificar usuário.")
        except Exception as e:
            self.console_print(f"ERRO: {e}\n")
            messagebox.showerror("Erro", str(e))

    def criar_usuario(self):
        """Cria um novo usuário no AD com verificação prévia automática."""
        # Validar campos
        nome = self.entry_nome.get().strip()
        setor = self.combo_setor.get()
        cargo = self.entry_cargo.get().strip()
        login = self.entry_login.get().strip()
        
        if not all([nome, setor, cargo, login]):
            messagebox.showerror("Erro", "Preencha todos os campos obrigatórios.")
            return
        
        # Obter OU
        ou = self.config.get("ous", {}).get(setor, "")
        if not ou:
            messagebox.showerror("Erro", f"OU não configurada para o setor '{setor}'.")
            return
        
        # ============================================
        # PASSO 1: VERIFICAÇÃO AUTOMÁTICA
        # ============================================
        self.console_print(f"\n{'='*60}\n")
        self.console_print(f"🔍 ETAPA 1: VERIFICAÇÃO DO USUÁRIO\n")
        self.console_print(f"{'='*60}\n")
        self.console_print(f"Login: {login}\n")
        self.console_print(f"Nome: {nome}\n")
        self.console_print(f"Setor: {setor}\n")
        self.console_print(f"OU de destino: {ou}\n\n")
        
        script_verify = self.base_dir / "scripts" / "verify_user.ps1"
        
        pode_criar = True
        usuario_existe = False
        usuario_desativado = False
        usuarios_similares = []
        
        if script_verify.exists():
            try:
                cmd_verify = [
                    "powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_verify),
                    "-Login", login,
                    "-NomeCompleto", nome
                ]
                
                resultado_verify = subprocess.run(
                    cmd_verify,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if resultado_verify.stdout:
                    try:
                        resposta_verify = json.loads(resultado_verify.stdout.strip())
                        
                        # Mostrar mensagens da verificação
                        for msg in resposta_verify.get("mensagens", []):
                            self.console_print(f"{msg}\n")
                        
                        usuario_existe = resposta_verify.get("usuario_existe", False)
                        usuario_desativado = resposta_verify.get("usuario_desativado", False)
                        usuarios_similares = resposta_verify.get("usuarios_similares", [])
                        
                        # Registrar log da verificação
                        self.log_evento("VERIFICAR_USUARIO", f"Verificação automática do login {login}", {
                            "login": login,
                            "existe": usuario_existe,
                            "desativado": usuario_desativado,
                            "similares": len(usuarios_similares)
                        })
                        
                        # Verificar se pode criar
                        if usuario_existe:
                            pode_criar = False
                            if usuario_desativado:
                                resp = messagebox.askyesno(
                                    "⚠️ Usuário Desativado",
                                    f"O usuário '{login}' JÁ EXISTE mas está DESATIVADO.\n\n"
                                    "Deseja REATIVAR este usuário em vez de criar um novo?\n\n"
                                    "• Sim = Ir para aba de Scripts para reativar\n"
                                    "• Não = Cancelar operação"
                                )
                                if resp:
                                    self.console_print("\n⚠️ Operação cancelada. Use 'Executar Scripts' para reativar.\n")
                                    self.notebook.select(self.tab_scripts)
                                return
                            else:
                                messagebox.showerror(
                                    "❌ Usuário Já Existe",
                                    f"O usuário '{login}' já existe e está ATIVO.\n\n"
                                    "Não é possível criar um usuário com este login.\n\n"
                                    "Sugestões:\n"
                                    "• Altere o nome/sobrenome\n"
                                    "• Adicione um número (ex: joao.silva2)"
                                )
                                return
                        
                        # Verificar usuários similares
                        if usuarios_similares:
                            nomes_similares = "\n".join([
                                f"• {s['login']} - {s['nome']} [{s['status']}]"
                                for s in usuarios_similares[:5]
                            ])
                            
                            total_similares = len(usuarios_similares)
                            msg_extras = f"\n\n(+ {total_similares - 5} outros...)" if total_similares > 5 else ""
                            
                            resp = messagebox.askyesno(
                                "⚠️ Usuários Similares Encontrados",
                                f"Foram encontrados {total_similares} usuários com nomes similares:\n\n"
                                f"{nomes_similares}{msg_extras}\n\n"
                                "ATENÇÃO: Verifique se não é o mesmo funcionário!\n\n"
                                "Deseja CONTINUAR com a criação mesmo assim?"
                            )
                            if not resp:
                                self.console_print("\n❌ Criação cancelada pelo usuário.\n")
                                return
                            else:
                                self.console_print("\n✅ Usuário confirmou: prosseguir com a criação.\n")
                    
                    except json.JSONDecodeError:
                        self.console_print(f"Aviso: Não foi possível processar verificação.\n")
                        self.console_print(f"Saída: {resultado_verify.stdout}\n")
                
            except subprocess.TimeoutExpired:
                self.console_print("⚠️ Timeout na verificação. Continuando sem verificar...\n")
            except Exception as e:
                self.console_print(f"⚠️ Erro na verificação: {e}. Continuando...\n")
        else:
            self.console_print("⚠️ Script de verificação não encontrado. Pulando verificação...\n")
        
        # ============================================
        # PASSO 2: CRIAÇÃO DO USUÁRIO
        # ============================================
        self.console_print(f"\n{'='*60}\n")
        self.console_print(f"✅ ETAPA 2: CRIAÇÃO DO USUÁRIO\n")
        self.console_print(f"{'='*60}\n")
        self.console_print(f"OU: {ou}\n")
        self.console_print(f"Modo: {'SIMULAÇÃO' if self.dry_run_var.get() else 'PRODUÇÃO'}\n\n")
        
        # Gerar senha
        senha = self.gerar_senha()
        
        # Obter grupos selecionados
        grupos = [g for g, var in self.grupos_vars.items() if var.get()]
        
        # Montar comando
        script_path = self.base_dir / "scripts" / "create_ad_user.ps1"
        
        dry_run = "-DryRun" if self.dry_run_var.get() else ""
        
        cmd = [
            "powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path),
            "-NomeCompleto", nome,
            "-Login", login,
            "-Setor", setor,
            "-Cargo", cargo,
            "-Senha", senha,
            "-OU", ou,
            "-Grupos", ",".join(grupos)
        ]
        
        if dry_run:
            cmd.append("-DryRun")
        
        try:
            resultado = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if resultado.stdout:
                resposta = json.loads(resultado.stdout.strip())
                
                if resposta.get("sucesso"):
                    # Sucesso
                    self.console_print(f"✅ {resposta.get('mensagem')}\n")
                    
                    # Mostrar relatório
                    relatorio = self.gerar_relatorio(nome, login, setor, cargo, senha, grupos, resposta)
                    self.resultado_text.delete(1.0, tk.END)
                    self.resultado_text.insert(tk.END, relatorio)
                    
                    # Registrar log
                    self.log_evento("CRIAR_USUARIO", f"Usuário {login} criado com sucesso", {
                        "login": login,
                        "nome": nome,
                        "setor": setor,
                        "grupos": grupos
                    })
                    
                    # Atualizar comando para executar no servidor
                    self.atualizar_comando_servidor(nome, login, setor, cargo, senha, ou, grupos)
                    
                    if not self.dry_run_var.get():
                        messagebox.showinfo("Sucesso", f"Usuário '{login}' criado com sucesso!\n\nA senha foi copiada para o relatório.\n\nO comando PowerShell foi gerado na aba 'Conectar Servidor'.")
                else:
                    # Erro
                    self.console_print(f"❌ {resposta.get('mensagem')}\n")
                    self.log_evento("ERRO_CRIAR_USUARIO", resposta.get('mensagem'), {"login": login})
                    messagebox.showerror("Erro", resposta.get('mensagem'))
            else:
                self.console_print(f"Erro: {resultado.stderr}\n")
                
        except subprocess.TimeoutExpired:
            self.console_print("ERRO: Timeout ao criar usuário.\n")
            messagebox.showerror("Erro", "Timeout ao criar usuário.")
        except json.JSONDecodeError as e:
            self.console_print(f"Erro ao processar resposta: {resultado.stdout}\n")
        except Exception as e:
            self.console_print(f"ERRO: {e}\n")
            messagebox.showerror("Erro", str(e))
    
    def gerar_relatorio(self, nome, login, setor, cargo, senha, grupos, resposta):
        """Gera relatório formatado para copiar."""
        data_hora = datetime.now().strftime("%d/%m/%Y %H:%M")
        
        relatorio = f"""
╔══════════════════════════════════════════════════════════════╗
║           RELATÓRIO DE CRIAÇÃO DE USUÁRIO                     ║
╠══════════════════════════════════════════════════════════════╣
║  Data/Hora: {data_hora:<48}║
╠══════════════════════════════════════════════════════════════╣
║  DADOS DO USUÁRIO:                                            ║
║  • Nome Completo: {nome:<42}║
║  • Login: {login:<50}║
║  • Setor: {setor:<50}║
║  • Cargo: {cargo:<50}║
╠══════════════════════════════════════════════════════════════╣
║  CREDENCIAIS:                                                 ║
║  • Senha Inicial: {senha:<42}║
║  • Trocar senha no primeiro login: SIM                        ║
╠══════════════════════════════════════════════════════════════╣
║  GRUPOS:                                                      ║
"""
        for grupo in grupos:
            relatorio += f"║  • {grupo:<57}║\n"
        
        relatorio += f"""╠══════════════════════════════════════════════════════════════╣
║  STATUS: {'SIMULAÇÃO' if self.dry_run_var.get() else 'CRIADO COM SUCESSO':<51}║
╚══════════════════════════════════════════════════════════════╝
"""
        return relatorio
    
    def executar_script(self):
        """Executa um script pré-aprovado."""
        nome_script = self.combo_script.get()
        
        if not nome_script:
            messagebox.showerror("Erro", "Selecione um script.")
            return
        
        # Encontrar script
        script = None
        for s in self.scripts_disponiveis:
            if s["nome"] == nome_script:
                script = s
                break
        
        if not script:
            return
        
        # Validar parâmetros obrigatórios
        for param in script.get("parametros", []):
            if param.get("obrigatorio"):
                valor = self.param_entries.get(param["nome"], None)
                if valor and not valor.get().strip():
                    messagebox.showerror("Erro", f"O parâmetro '{param['label']}' é obrigatório.")
                    return
        
        # Montar comando
        script_path = self.base_dir / "scripts" / script["arquivo"]
        
        if not script_path.exists():
            messagebox.showerror("Erro", f"Script não encontrado: {script['arquivo']}")
            return
        
        cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
        
        for param in script.get("parametros", []):
            entry = self.param_entries.get(param["nome"])
            if entry:
                valor = entry.get().strip()
                if valor:
                    cmd.extend([f"-{param['nome']}", valor])
                elif param["nome"] == "NovaSenha":
                    # Gerar senha se não informada
                    valor = self.gerar_senha()
                    cmd.extend([f"-{param['nome']}", valor])
        
        if self.dry_run_var.get():
            cmd.append("-DryRun")
        
        self.console_print(f"\n{'='*50}\n")
        self.console_print(f"Executando: {nome_script}\n")
        self.console_print(f"Modo: {'SIMULAÇÃO' if self.dry_run_var.get() else 'PRODUÇÃO'}\n")
        
        try:
            resultado = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if resultado.stdout:
                try:
                    resposta = json.loads(resultado.stdout.strip())
                    if resposta.get("sucesso"):
                        self.console_print(f"✅ {resposta.get('mensagem')}\n")
                        self.log_evento("EXECUTAR_SCRIPT", f"Script {nome_script} executado", resposta.get("dados", {}))
                    else:
                        self.console_print(f"❌ {resposta.get('mensagem')}\n")
                        self.log_evento("ERRO_SCRIPT", resposta.get('mensagem'), {"script": nome_script})
                except json.JSONDecodeError:
                    self.console_print(f"Saída: {resultado.stdout}\n")
            
            if resultado.stderr:
                self.console_print(f"Erros: {resultado.stderr}\n")
                
        except subprocess.TimeoutExpired:
            self.console_print("ERRO: Timeout ao executar script.\n")
        except Exception as e:
            self.console_print(f"ERRO: {e}\n")
    
    def log_evento(self, acao, mensagem, dados=None):
        """Registra um evento no arquivo de log."""
        logs_dir = self.base_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        data_hoje = datetime.now().strftime("%Y-%m-%d")
        log_file = logs_dir / f"audit_{data_hoje}.log"
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        usuario = self.info_ambiente.get("usuario_atual", os.getenv("USERNAME", "desconhecido"))
        
        log_entry = {
            "timestamp": timestamp,
            "usuario": usuario,
            "acao": acao,
            "mensagem": mensagem,
            "dados": dados or {},
            "dry_run": self.dry_run_var.get()
        }
        
        try:
            with open(log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
        except Exception as e:
            self.console_print(f"AVISO: Não foi possível gravar log: {e}\n")
    
    def carregar_logs(self):
        """Carrega e exibe os logs recentes."""
        logs_dir = self.base_dir / "logs"
        
        if not logs_dir.exists():
            self.logs_text.delete(1.0, tk.END)
            self.logs_text.insert(tk.END, "Nenhum log encontrado.")
            return
        
        # Listar arquivos de log
        log_files = sorted(logs_dir.glob("audit_*.log"), reverse=True)
        
        self.logs_text.delete(1.0, tk.END)
        
        if not log_files:
            self.logs_text.insert(tk.END, "Nenhum log encontrado.")
            return
        
        # Mostrar logs dos últimos arquivos
        for log_file in log_files[:5]:  # Últimos 5 dias
            self.logs_text.insert(tk.END, f"\n{'='*60}\n")
            self.logs_text.insert(tk.END, f"📅 {log_file.stem}\n")
            self.logs_text.insert(tk.END, f"{'='*60}\n\n")
            
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            self.logs_text.insert(
                                tk.END,
                                f"[{entry['timestamp']}] [{entry['usuario']}] {entry['acao']}: {entry['mensagem']}\n"
                            )
                        except:
                            self.logs_text.insert(tk.END, line)
            except Exception as e:
                self.logs_text.insert(tk.END, f"Erro ao ler log: {e}\n")
    
    def abrir_pasta_logs(self):
        """Abre a pasta de logs no explorador."""
        logs_dir = self.base_dir / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        try:
            os.startfile(logs_dir)
        except Exception as e:
            messagebox.showerror("Erro", f"Não foi possível abrir a pasta: {e}")
    
    def copiar_logs(self):
        """Copia os logs para a área de transferência."""
        conteudo = self.logs_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(conteudo)
        messagebox.showinfo("Copiado", "Logs copiados para a área de transferência.")
    
    def copiar_relatorio(self):
        """Copia o relatório para a área de transferência."""
        conteudo = self.resultado_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(conteudo)
        messagebox.showinfo("Copiado", "Relatório copiado para a área de transferência.")
    
    def copiar_console(self):
        """Copia o conteúdo do console para a área de transferência."""
        conteudo = self.console.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(conteudo)
        messagebox.showinfo("Copiado", "Saída copiada para a área de transferência.")
    
    def limpar_console(self):
        """Limpa o console."""
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)
    
    def limpar_formulario_usuario(self):
        """Limpa o formulário de criação de usuário."""
        self.entry_nome.delete(0, tk.END)
        self.combo_setor.set("")
        self.entry_cargo.delete(0, tk.END)
        self.entry_login.config(state="normal")
        self.entry_login.delete(0, tk.END)
        self.entry_login.config(state="readonly")
        self.resultado_text.delete(1.0, tk.END)
        
        # Resetar grupos
        for var in self.grupos_vars.values():
            var.set(False)
        for widget in self.grupos_setor_frame.winfo_children():
            widget.destroy()
    
    def console_print(self, texto):
        """Adiciona texto ao console."""
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, texto)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)


def main():
    """Função principal."""
    root = tk.Tk()
    
    # Configurar estilo
    style = ttk.Style()
    style.theme_use('clam')
    
    # Cores personalizadas
    style.configure("Accent.TButton", foreground="white", background="#0066cc")
    
    app = InfraToolsApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
