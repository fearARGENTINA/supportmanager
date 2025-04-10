import ldap
from ldap.controls import SimplePagedResultsControl

class LdapRetriever:
    def __init__(self, ldapHost, ldapPort, ldapDN, ldapPassword, useSSL=False):
        self.ldapHost = ldapHost
        self.ldapPort = ldapPort
        self.ldapDN = ldapDN
        self.ldapPassword = ldapPassword
        self.useSSL = useSSL
        
        if useSSL:
            self.ldapServer = f"ldaps://{ldapHost}:{ldapPort}"
        else:
            self.ldapServer = f"ldap://{ldapHost}:{ldapPort}"

    def bind(self):
        try:
            if self.useSSL:
                ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap_conn = ldap.initialize(self.ldapServer)
        
        except ldap.SERVER_DOWN:
            print("Server down")
            return None

        try:
            ldap_conn.protocol_version = ldap.VERSION3
            ldap_conn.set_option(ldap.OPT_REFERRALS, 0)

            if self.useSSL:
                #ldap_conn.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
                ldap_conn.set_option(ldap.OPT_X_TLS_DEMAND, True)

            ldap_conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5.0)
            ldap_conn.simple_bind_s(self.ldapDN, self.ldapPassword)
        except ldap.INVALID_CREDENTIALS:
            print("User or password incorrect")
            return None

        return ldap_conn
    
    def getAllComputers(self, baseOU):
        l = self.bind()

        if l is None:
            return None
        
        criteria = "(&(objectClass=computer))"
        attributes = [ "distinguishedName", "Name" ]

        try:
            page_control = SimplePagedResultsControl(True, size=1000, cookie='')

            result = []
            pages = 0
            response = l.search_ext(baseOU, ldap.SCOPE_SUBTREE, criteria, attributes, serverctrls=[page_control])

            while True:
                pages += 1
                rtype, rdata, rmsgid, serverctrls = l.result3(response)
                result.extend(rdata)
                controls = [
                    control 
                        for control in serverctrls
                    if control.controlType == SimplePagedResultsControl.controlType
                ]

                if not controls:
                    print('The server ignores RFC 2696 control')
                    break

                if not controls[0].cookie:
                    break

                page_control.cookie = controls[0].cookie       

                response = l.search_ext(baseOU, ldap.SCOPE_SUBTREE, criteria, attributes, serverctrls=[page_control])
        except Exception as e:
            print(str(e))
            return None

        results = [entry for dn, entry in result if isinstance(entry, dict)]

        return results

    def addComputerToGroup(self, groupDN, computerDN):
        l = self.bind()

        if l is None:
            return None

        try:
            l.modify_s(
                groupDN,
                [
                    (ldap.MOD_ADD, 'member', [computerDN])
                ]
            )
        except ldap.ALREADY_EXISTS:
            return -2
        except Exception as e:
            print(str(e))
            return -1
        
        return 1