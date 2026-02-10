import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes
from src.config import settings
from src.security import restricted
from src.core.wazuh_client import WazuhOrchestrator
from src.core.simulator import AttackSimulator

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

wazuh = WazuhOrchestrator()
simulator = AttackSimulator()

@restricted
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ **Sentinel SOC Automator**\n\nStatus: `ONLINE`\n"
        "/status - Health Check da Infraestrutura\n"
        "/simulate - Injetar Vetor de Ataque (Red Team)\n"
        "/check - Triagem de Incidentes (Blue Team)",
        parse_mode='Markdown'
    )

@restricted
async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await wazuh._get_token()
        msg = "✅ **SISTEMA OPERACIONAL**\nConexão com Wazuh Manager: `ESTÁVEL`"
    except Exception as e:
        msg = f"❌ **ERRO CRÍTICO**\nFalha de conexão com SIEM: `{e}`"
    await update.message.reply_text(msg, parse_mode='Markdown')

@restricted
async def simulate_attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("⚠️ **RED TEAM ALERT**\nIniciando simulação de Brute Force SSH...")
    attacker_ip = await simulator.run_ssh_brute_force()
    await update.message.reply_text(
        f"📡 **INJEÇÃO CONCLUÍDA**\n"
        f"Vetor: `SSH Brute Force`\n"
        f"Origem Simulada: `{attacker_ip}`\n"
        f"Aguarde a correlação do SIEM e execute `/check`.",
        parse_mode='Markdown'
    )

@restricted
async def check_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE):
    alerts = await wazuh.get_recent_alerts()
    if not alerts:
        await update.message.reply_text("✅ Nenhum incidente crítico pendente de triagem.")
        return

    context.bot_data['last_alerts'] = {alert.get('id'): alert for alert in alerts}

    for alert in alerts:
        rule = alert.get('rule', {}).get('description', 'N/A')
        agent = alert.get('agent', {}).get('id', '000')
        src_ip = alert.get('data', {}).get('srcip', 'N/A')
        alert_id = alert.get('id')
        reputation = await wazuh.check_ip_reputation(src_ip) if src_ip != 'N/A' else "N/A"

        keyboard = [
            [
                InlineKeyboardButton("🚫 Bloquear IP", callback_data=f"block|{agent}|{src_ip}"),
                InlineKeyboardButton("✅ Falso Positivo", callback_data=f"fp|{alert_id}")
            ],
            [
                InlineKeyboardButton("🔍 Ver Log Completo", callback_data=f"details|{alert_id}")
            ]
        ]
        
        msg = (
            f"🚨 **INCIDENTE DETECTADO**\n"
            f"ID: `{alert_id}`\n"
            f"Regra: {rule}\n"
            f"Agente Alvo: `{agent}`\n"
            f"Origem: `{src_ip}`\n"
            f"Intel: {reputation}"
        )
        await update.message.reply_text(msg, reply_markup=InlineKeyboardMarkup(keyboard), parse_mode='Markdown')

@restricted
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    data = query.data.split('|')
    action = data[0]
    
    if action == "block":
        agent, ip = data[1], data[2]
        success, resp = await wazuh.trigger_active_response(agent, ip)
        if success:
            await query.edit_message_text(f"🛡️ **CONTRAMEDIDA EXECUTADA**\nHost `{ip}` isolado no Agente `{agent}`.", parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ Falha na execução: `{resp}`", parse_mode='Markdown')

    elif action == "details":
        alert_id = data[1]
        alert = context.bot_data.get('last_alerts', {}).get(alert_id)
        if alert:
            full_log = alert.get('full_log', 'N/A')
            agent = alert.get('agent', {}).get('id', '000')
            ip = alert.get('data', {}).get('srcip', 'N/A')
            kb = [[InlineKeyboardButton("🚫 Bloquear", callback_data=f"block|{agent}|{ip}")]]
            
            await query.edit_message_text(
                f"🔍 **ANÁLISE FORENSE**\nLog Bruto:\n```\n{full_log}\n```",
                reply_markup=InlineKeyboardMarkup(kb),
                parse_mode='Markdown'
            )
        else:
            await query.edit_message_text("⚠️ Sessão do alerta expirada. Execute /check novamente.")

    elif action == "fp":
        await query.edit_message_text("📝 Classificado como Falso Positivo. Incidente encerrado.")

def main():
    if not settings.TELEGRAM_TOKEN:
        logger.fatal("TELEGRAM_TOKEN não encontrado. Abortando.")
        return

    application = Application.builder().token(settings.TELEGRAM_TOKEN).build()
    
    handlers = [
        CommandHandler("start", start),
        CommandHandler("status", status),
        CommandHandler("simulate", simulate_attack),
        CommandHandler("check", check_alerts),
        CallbackQueryHandler(button_handler)
    ]
    application.add_handlers(handlers)

    logger.info("Sentinel SOC Automator iniciado...")
    application.run_polling()

if __name__ == '__main__':
    main()