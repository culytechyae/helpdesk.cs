import os
from production_config import ProductionConfig, DevelopmentConfig, config as _config


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    cfg = _config.get(env, DevelopmentConfig)
    # Ensure FLASK_ENV is available in app.config (Flask 3.x removed it as a default)
    cfg.FLASK_ENV = env
    return cfg
