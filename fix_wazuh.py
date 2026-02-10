import subprocess
import os
import sys

INJECTION_BLOCK = """
  <!-- INJEÇÃO AUTOMATICA - SENTINEL SOC AUTOMATOR -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>0.0.0.0/0</allowed-ips>
    <local_ip>0.0.0.0</local_ip>
  </remote>

  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <level>15</level>
    <timeout>60</timeout>
  </active-response>
  <!-- FIM DA INJEÇÃO -->
"""

def run_command(cmd: str) -> bool:
    print(f"🔄 Executing: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Error: {result.stderr.strip()}")
        return False
    return True

def main():
    print("🔧 Iniciando Protocolo de Patch do Wazuh...")
    if not run_command("docker cp wazuh-manager:/var/ossec/etc/ossec.conf temp_ossec.xml"):
        sys.exit(1)

    try:
        with open("temp_ossec.xml", "r", encoding="utf-8") as f:
            content = f.read()
        
        if "SENTINEL SOC AUTOMATOR" in content:
            print("⚠️  Patch já aplicado anteriormente. Reiniciando para garantir estado.")
        else:
            last_tag = "</ossec_config>"
            if last_tag not in content:
                print("❌ Erro Crítico: Arquivo de configuração inválido.")
                sys.exit(1)
            
            new_content = content.replace(last_tag, INJECTION_BLOCK + "\n" + last_tag)
            with open("temp_ossec.xml", "w", encoding="utf-8", newline='\n') as f:
                f.write(new_content)
            
            print("✅ Patch aplicado com sucesso.")
            if not run_command("docker cp temp_ossec.xml wazuh-manager:/var/ossec/etc/ossec.conf"):
                sys.exit(1)
            
            print("🛡️ Ajustando permissões do arquivo de configuração...")
            run_command("docker exec -u 0 wazuh-manager chown wazuh:wazuh /var/ossec/etc/ossec.conf")
            run_command("docker exec -u 0 wazuh-manager chmod 660 /var/ossec/etc/ossec.conf")

        print("🚀 Reiniciando Wazuh Manager para aplicar as mudanças...")
        run_command("docker restart wazuh-manager")
        print("\n✅ Processo concluído! Aguarde ~60s para a estabilização do serviço.")
    
    except Exception as e:
        print(f"❌ Erro fatal no script: {e}")
    finally:
        if os.path.exists("temp_ossec.xml"):
            os.remove("temp_ossec.xml")

if __name__ == "__main__":
    main()