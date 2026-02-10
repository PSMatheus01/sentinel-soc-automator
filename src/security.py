from functools import wraps
from telegram import Update
from telegram.ext import ContextTypes
import logging
from .config import settings

logger = logging.getLogger(__name__)

def restricted(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user_id = update.effective_user.id
        if user_id not in settings.ALLOWED_USER_IDS:
            logger.warning(f"Acesso não autorizado bloqueado para o User ID: {user_id}")
            return
        return await func(update, context, *args, **kwargs)
    return wrapped