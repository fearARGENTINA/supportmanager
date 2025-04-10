from flask_wtf import Form
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired
from app import db, app
 
class User(db.Model):
    sid = db.Column(db.String(512), primary_key=True)
    dn = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255))
    permissions = db.Column(db.String(2048))
    def __init__(self, sid, dn, username, permissions):
        self.sid = sid
        self.dn = dn
        self.username = username
        self.permissions = permissions

    def __repr__(self):
        return self.dn

    def get_id(self):
        return self.dn

    def is_active(self):
        return True

    def is_authenticated(self):
        return True
    
    def is_anonymous(self):
        return False

    def get_permissions(self):
        return self.permissions.split(',')
    
    def is_usb_activator(self):
        return "Activadores_USB" in self.get_permissions()
    
    def is_inventory_admin(self):
        return "Inventario_Admin" in self.get_permissions()