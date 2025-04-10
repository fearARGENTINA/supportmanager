from flask import request, render_template, flash, redirect, \
    url_for, Blueprint, g, session
from flask_login import current_user, login_user, \
    logout_user, login_required
from app import login_manager, ldap_manager, db, app
from app.auth.models import User
from flask_ldap3_login.forms import LDAPLoginForm
from app.helper.helpers import LdapRetriever
import requests
import json
from datetime import timedelta

auth = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(dn):
    try:
        return User.query.filter_by(dn=dn).first()
    except Exception:
        return None

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    user_sid = data.get("objectSid")

    permissions = []
    for permissionName, groupDN in app.config.get('LDAP_GROUPS_ADMIN').items():
        if groupDN in data.get("memberOf", []):
            permissions += [permissionName]

    if len(permissions):
        print(permissions)
        user = User.query.filter_by(dn=dn).first()

        if not user:
            user = User(
                user_sid,
                dn, 
                username,
                ','.join(permissions)                
            )
            db.session.add(user)
            db.session.commit()
        return user

    else:
        app.logger.info(f"{request.method} /login from {request.remote_addr}. Failed login for user {data.get('sAMAccountName')} because group membership", extra={
            "client.ip": request.remote_addr,
            "user.name": data.get('sAMAccountName'),
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /login from {request.remote_addr}. Failed login for user {data.get('sAMAccountName')} because group membership",
            "event.action": "LOGIN",
            "event.outcome": "failure"
        }) 

@auth.before_request
def get_current_user():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=20)
    session.modified = True
    g.user = current_user
 
@auth.route('/')
@auth.route('/home')
def home():
    if not current_user.is_authenticated:
        app.logger.info(f"{request.method} /,/home from {request.remote_addr} is not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /,/home from {request.remote_addr} is not authenticated",
            "event.action": "HOME",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    app.logger.info(f"{request.method} /,/home from {request.remote_addr} authenticated as {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "http.request.body.content": f"{request.method} /,/home from {request.remote_addr} authenticated as {current_user.username}",
        "event.action": "HOME",
        "event.outcome": "success"
    })
    
    user = current_user
    usb_activator = user.is_usb_activator()
    inventory_admin = user.is_inventory_admin()

    return render_template('home.html', is_usb_activator=usb_activator, is_inventory_admin=inventory_admin)

@auth.route('/inventory')
def inventory():
    if not current_user.is_authenticated:
        app.logger.info(f"{request.method} /inventory from {request.remote_addr} is not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventory from {request.remote_addr} is not authenticated",
            "event.action": "INVENTORY",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    if not current_user.is_inventory_admin():
        app.logger.info(f"{request.method} /inventory {request.remote_addr} is authenticated but dont have permission Inventory Admin", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventory {request.remote_addr} is authenticated but dont have permission Inventory Admin",
            "event.action": "INVENTORY",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    app.logger.info(f"{request.method} /inventory from {request.remote_addr} authenticated as {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "http.request.body.content": f"{request.method} /inventory from {request.remote_addr} authenticated as {current_user.username}",
        "event.action": "INVENTORY",
        "event.outcome": "success"
    })
    
    r = requests.get("https://inventario.local/inventories?orderBy=id&sortOrder=asc")

    records = json.loads(r.text)
    colnames = []
    if len(records):
        colnames = records[0].keys()

    return render_template('inventory.html', colnames=colnames, records=records)

@auth.route('/inventory_ssp')
def inventory_ssp():
    if not current_user.is_authenticated:
        app.logger.info(f"{request.method} /inventory_ssp from {request.remote_addr} is not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventory_ssp from {request.remote_addr} is not authenticated",
            "event.action": "INVENTORY_SSP",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    if not current_user.is_inventory_admin():
        app.logger.info(f"{request.method} /inventory_ssp {request.remote_addr} is authenticated but dont have permission Inventory Admin", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventory_ssp {request.remote_addr} is authenticated but dont have permission Inventory Admin",
            "event.action": "INVENTORY_SSP",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    app.logger.info(f"{request.method} /inventory_ssp from {request.remote_addr} authenticated as {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "http.request.body.content": f"{request.method} /inventory_ssp from {request.remote_addr} authenticated as {current_user.username}",
        "event.action": "INVENTORY_SSP",
        "event.outcome": "success"
    })
    
    r = requests.get("https://inventario.local/inventories/columns")

    colnames = json.loads(r.text)
    
    return render_template('inventory_ssp.html', colnames=colnames)

@auth.route('/inventories_lastsync')
def inventory_lastsync():
    if not current_user.is_authenticated:
        app.logger.info(f"{request.method} /inventories_lastsync from {request.remote_addr} is not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventories_lastsync from {request.remote_addr} is not authenticated",
            "event.action": "INVENTORIES_LASTSYNC",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    if not current_user.is_inventory_admin():
        app.logger.info(f"{request.method} /inventories_lastsync {request.remote_addr} is authenticated but dont have permission Inventory Admin", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /inventories_lastsync {request.remote_addr} is authenticated but dont have permission Inventory Admin",
            "event.action": "INVENTORIES_LASTSYNC",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    app.logger.info(f"{request.method} /inventories_lastsync from {request.remote_addr} authenticated as {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "http.request.body.content": f"{request.method} /inventories_lastsync from {request.remote_addr} authenticated as {current_user.username}",
        "event.action": "INVENTORIES_LASTSYNC",
        "event.outcome": "success"
    })
    
    r = requests.get("https://inventario.local/inventories/lastSync/columns")

    colnames = json.loads(r.text)
    
    return render_template('inventories_lastsync.html', colnames=colnames)

@auth.route('/usbenabler')
def usbenabler():
    if not current_user.is_authenticated:
        app.logger.info(f"{request.method} /usbenabler from {request.remote_addr} is not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /usbenabler from {request.remote_addr} is not authenticated",
            "event.action": "USBENABLER",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    if not current_user.is_usb_activator():
        app.logger.info(f"{request.method} /usbenabler {request.remote_addr} is authenticated but dont have permission USB Activator", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /usbenabler {request.remote_addr} is authenticated but dont have permission USB Activator",
            "event.action": "USBENABLER",
            "event.outcome": "failure"
        })
        return redirect(url_for('auth.login'))

    app.logger.info(f"{request.method} /usbenabler from {request.remote_addr} authenticated as {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "http.request.body.content": f"{request.method} /usbenabler from {request.remote_addr} authenticated as {current_user.username}",
        "event.action": "USBENABLER",
        "event.outcome": "success"
    })

    ldapPort = app.config.get('LDAP_PORT', 389)

    ldapRetriever = LdapRetriever(app.config['LDAP_HOST'], ldapPort, app.config['LDAP_BIND_USER_DN'], app.config['LDAP_BIND_USER_PASSWORD'], useSSL=app.config.get('LDAP_USE_SSL', False))

    computers = ldapRetriever.getAllComputers(app.config['LDAP_COMPUTERS_DN'])

    return render_template('usbenabler.html', computers=computers)
 
@auth.route('/enable_usb', methods=['POST'])
def enableUSB():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))

    if not current_user.is_usb_activator():
        return redirect(url_for('auth.login'))

    computer = request.form.get('computadoras').encode()
    ticket = request.form.get('ticket')

    if not ticket or not len(ticket):
        flash("La completitud del campo ticket es obligatoria. No se ejecuto la activacion de USB's!", "danger")
        return redirect(url_for('auth.login'))

    allStatus = []
    for ldapHost in app.config['LDAP_ALL_HOSTS']:
        try:
            ldapPort = app.config.get('LDAP_PORT', 389)

            ldapRetriever = LdapRetriever(ldapHost, ldapPort, app.config['LDAP_BIND_USER_DN'], app.config['LDAP_BIND_USER_PASSWORD'], useSSL=app.config.get('LDAP_USE_SSL', False))
            
            allStatus += [ldapRetriever.addComputerToGroup(app.config['LDAP_GROUP_EXCEPCION_BLOQUEO'], computer)]
        except Exception as e:
            allStatus += [-1]

    if 1 in allStatus:
        app.logger.info(f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, successful", extra={
            "client.ip": request.remote_addr,
            "user.name": current_user.username,
            "host.hostname": computer,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, successful",
            "event.action": "ENABLE_USB",
            "event.outcome": "success",
            "event.id": ticket
        })
        flash("La operación se ejecuto con exito. A continuación reinicie el equipo destino y ejecute \"gpupdate /force\" sobre el mismo.", "success")
    elif -2 in allStatus:
        app.logger.info(f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, failed (Computer already exists in group)", extra={
            "client.ip": request.remote_addr,
            "user.name": current_user.username,
            "host.hostname": computer,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, failed (Computer already exists in group)",
            "event.action": "ENABLE_USB",
            "event.outcome": "failure",
            "event.id": ticket
        })
        flash("El equipo ya se encuentra exceptuado. A continuación reinicie el equipo destino y ejecute \"gpupdate /force\" sobre el mismo.", "success")
    elif -1 in allStatus:
        app.logger.info(f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, failed", extra={
            "client.ip": request.remote_addr,
            "user.name": current_user.username,
            "host.hostname": computer,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /enable_usb from {request.remote_addr} authenticated as {current_user.username}. Enabling usb for computer {computer}, ticket {ticket}, failed",
            "event.action": "ENABLE_USB",
            "event.outcome": "failure",
            "event.id": ticket
        })
        flash("Hubo un problema con el servidor LDAP. Intente nuevamente.", "danger")

    return redirect(url_for('auth.login'))

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        app.logger.info(f"{request.method} /login from {request.remote_addr} authenticated as {current_user.username}, redirecting...", extra={
            "client.ip": request.remote_addr,
            "user.name": current_user.username,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /login from {request.remote_addr} authenticated as {current_user.username}, redirecting...",
            "event.action": "LOGIN",
            "event.outcome": "success"
        })
        return redirect(url_for('auth.home'))

    form = LDAPLoginForm()
    form.submit.label.text = "Iniciar sesión"
    
    if request.method == 'GET':
        app.logger.info(f"{request.method} /login from {request.remote_addr} not authenticated", extra={
            "client.ip": request.remote_addr,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /login from {request.remote_addr} not authenticated",
            "event.action": "LOGIN",
            "event.outcome": "unknown"
        })
    
    if request.method == 'POST':
        if not form.validate_on_submit() or not form.user:
            flash(
                'Usuario o contraseña incorrectos. Inicie sesión nuevamente.',
                'danger')
            
            app.logger.info(f"{request.method} /login from {request.remote_addr}. Failed login for user {form.username.data}", extra={
                "client.ip": request.remote_addr,
                "user.name": form.username.data,
                "http.request.method": request.method,
                "http.request.body.content": f"{request.method} /login from {request.remote_addr}. Failed login for user {form.username.data}",
                "event.action": "LOGIN",
                "event.outcome": "failure"
            })
            return render_template('login.html', form=form)
 
        app.logger.info(f"{request.method} /login from {request.remote_addr}. Successful logon for user {form.username.data}", extra={
            "client.ip": request.remote_addr,
            "user.name": form.username.data,
            "http.request.method": request.method,
            "http.request.body.content": f"{request.method} /login from {request.remote_addr}. Successful logon for user {form.username.data}",        
            "event.action": "LOGIN",
            "event.outcome": "success"
        })
        login_user(form.user, remember=False)
        flash('Has iniciado sesión correctamente', 'success')
        return redirect(url_for('auth.home'))
        
    if form.errors:
        flash(form.errors, 'danger')

    return render_template('login.html', form=form)
 
@auth.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
        
    app.logger.info(f"{request.method} /logout from {request.remote_addr}. Logout for user {current_user.username}", extra={
        "client.ip": request.remote_addr,
        "user.name": current_user.username,
        "http.request.method": request.method,
        "event.action": "LOGOUT",
        "event.outcome": "success",
        "http.request.body.content": f"{request.method} /logout from {request.remote_addr}. Logout for user {current_user.username}"
    })
    
    db.session.delete(current_user)
    db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))