import os

basedir = os.path.abspath(os.path.dirname(__file__))

#basedir = "/home/iolenterprises/iol-invoice-pythonanywhere"

class Config(object):
    # main config
    SECRET_KEY = os.getenv("APP_SECRET_KEY")
    SECURITY_PASSWORD_SALT = os.getenv("APP_SECURITY_PASSWORD_SALT")
    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # mail settings
  
    

    # gmail authentication
    MAIL_USERNAME = os.getenv("APP_MAIL_USERNAME")
    MAIL_PASSWORD = os.getenv("APP_MAIL_PASSWORD")
    # mail accounts
    MAIL_DEFAULT_SENDER = os.getenv("APP_MAIL_USERNAME_SENDER")
    RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_KEY")
    SECRET_SITE_KEY = os.getenv("SECRET_KEY_RECAPTCHA")
    #DROPBOX_ACCESS_TOKEN = os.getenv("DROPBOX_TOKEN")
    B2_KEY_ID = os.getenv("APPLICATION_KEY_ID")
    B2_APPLICATION_KEY = os.getenv("APPLICATION_KEY")

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")


class ProductionConfig(Config):
    DEBUG = False


class StagingConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class DevelopmentConfig(Config):
    DEVELOPMENT = True
    DEBUG = True


class TestingConfig(Config):
    TESTING = True
