from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_ldap3_login import LDAP3LoginManager
import os

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['WTF_CSRF_SECRET_KEY'] = os.getenv('WTF_CSRF_SECRET_KEY')
app.config['LDAP_HOST'] = "dc01.local"
app.config['LDAP_PORT'] = 636
app.config['LDAP_USE_SSL'] = True
app.config['LDAP_ALL_HOSTS'] = [ "dc01.local", "dc02.local", "dc03.local" ]
app.config['LDAP_BASE_DN'] = "DC=domain,DC=local"
app.config['LDAP_USER_DN'] = "OU=Usuarios"
app.config['LDAP_GROUP_DN'] = "OU=Grupos de seguridad"
app.config['LDAP_USER_RDN_ATTR'] = "CN"
app.config['LDAP_USER_LOGIN_ATTR'] = "sAmAccountName"
app.config['LDAP_USER_SEARCH_SCOPE'] = "SUBTREE"
app.config['LDAP_BIND_USER_DN'] = os.getenv('LDAP_BIND_USER_DN')
app.config['LDAP_BIND_USER_PASSWORD'] = os.getenv('LDAP_BIND_USER_PASSWORD')
app.config['LDAP_COMPUTERS_DN'] = "OU=Equipos,DC=domain,DC=local"
#app.config['LDAP_SEARCH_FOR_GROUPS'] = False
app.config['LDAP_GROUPS_ADMIN'] = {
    "Activadores_USB": "CN=Activadores_USB,OU=Grupos de seguridad,DC=domain,DC=local",
    "Inventario_Admin": "CN=Inventario_Admin,OU=Grupos de seguridad,DC=domain,DC=local"
}
app.config['LDAP_GROUP_EXCEPCION_BLOQUEO'] = "CN=Excepcion_Bloqueo_USB,OU=Grupos de seguridad,DC=domain,DC=local"

db = SQLAlchemy(app)
 
app.secret_key = os.getenv('SECRET_KEY')
 
login_manager = LoginManager()
ldap_manager = LDAP3LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

from app.auth.views import auth
app.register_blueprint(auth)
 
db.create_all()