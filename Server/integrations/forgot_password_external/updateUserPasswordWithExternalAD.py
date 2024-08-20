# coding: utf-8
# oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
# Copyright (c) 2020, Gluu
#
# Author: Christian Eland
# Modified: Mobarak Hosen Shakil

from org.xdi.oxauth.service import AuthenticationService
from org.gluu.oxauth.service import UserService
from org.gluu.oxauth.auth import Authenticator
from org.xdi.oxauth.security import Identity
from org.xdi.model.custom.script.type.auth import PersonAuthenticationType
from org.xdi.service.cdi.util import CdiUtil
from org.xdi.util import StringHelper
from org.xdi.oxauth.util import ServerUtil
from org.gluu.oxauth.service.common import ConfigurationService, EncryptionService
from org.gluu.jsf2.message import FacesMessages
from javax.faces.application import FacesMessage
from org.gluu.persist.exception import AuthenticationException

import smtplib
import json
import random
import string
import re

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from javax.naming import Context, InitialContext, CommunicationException, AuthenticationException, NameNotFoundException
from javax.naming.directory import InitialDirContext, ModificationItem, BasicAttribute, SearchControls
from java.util import Arrays, Hashtable


class EmailValidator():
    '''
    Class to check e-mail format
    '''
    regex = '^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$'

    def check(self, email):
        '''
        Check if email format is valid
        returns: boolean
        '''

        if(re.search(self.regex,email)):
            print "Forgot Password - %s is a valid email format" % email
            return True
        else:
            print "Forgot Password - %s is an invalid email format" % email
            return False

class Token:
    #class that deals with string token
    def generateToken(self):
        ''' method to generate token string
        returns: String
        '''
        # token length
        length = 8

        print "Forgot Password - Generating token"
        # generate token (UPPERCASE letters and Digits)
        token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(length))
        

        return token


class EmailSender():
    #class that sends e-mail through smtp

    def getSmtpConfig(self):
        '''
        get SMTP config from Gluu Server
        return dict
        '''
       
        smtpconfig = CdiUtil.bean(ConfigurationService).getConfiguration().getSmtpConfiguration()
        
        if smtpconfig is None:
            print "Forgot Password - SMTP CONFIG DOESN'T EXIST - Please configure"

        else:
            print "Forgot Password - SMTP CONFIG FOUND"
            encryptionService = CdiUtil.bean(EncryptionService)
            smtp_config = {
                'host' : smtpconfig.getHost(),
                'port' : smtpconfig.getPort(),
                'user' : smtpconfig.getUserName(),
                'from' : smtpconfig.getFromEmailAddress(),
                'pwd_decrypted' : encryptionService.decrypt(smtpconfig.getPassword()),
                'req_ssl' : smtpconfig.getConnectProtection(),
                'requires_authentication' : smtpconfig.isRequiresAuthentication(),
                'server_trust' : smtpconfig.isServerTrust()
            }

        return smtp_config            

    def sendEmail(self,useremail,token):
        '''
        send token by e-mail to useremail
        '''
        # server connection 
        smtpconfig = self.getSmtpConfig()
        host = str(smtpconfig.get('host'))
        port = smtpconfig.get('port')
        user = str(smtpconfig.get('user'))
        user_pass = str(smtpconfig.get('pwd_decrypted'))
        sender = str(smtpconfig.get('from'))
        receiver = str(useremail)
        
        try:
            s = smtplib.SMTP(host, port)
            if smtpconfig['requires_authentication']:
                if smtpconfig['req_ssl'] is not None:
                    s.starttls()
                s.login(user, user_pass)
        
            #message setup
            msg = MIMEMultipart() #create message
            
            message = "Here is your token: %s" % token
            msg['From'] = sender
            msg['To'] = receiver
            msg['Subject'] = "Password Reset Request" #subject

            # attach message body
            msg.attach(MIMEText(message, 'plain'))

            # send email (python2)
            s.sendmail(sender,receiver,msg.as_string())
            
            # after sent, delete
            del msg

            #terminating session
            s.quit()

        except smtplib.SMTPAuthenticationError as err:
            print "Forgot Password - SMTPAuthenticationError - %s - %s" % (user,user_pass)
            print err

        except smtplib.SMTPSenderRefused as err:
            print "Forgot Password - SMTPSenderRefused - " + err
        except smtplib.SMTPRecipientsRefused as err:
            print "Forgot Password - SMTPRecipientsRefused - " + err
        except smtplib.SMTPDataError as err:
            print "Forgot Password - SMTPDataError - " + err
        except smtplib.SMTPHeloError as err:
            print "Forgot Password - SMTPHeloError - " + err
        except:
            print "Forgot Password - Not Found - Failed to send  your message. Error not found"


class PersonAuthentication(PersonAuthenticationType):

    def __init__(self, currentTimeMillis):
        self.currentTimeMillis = currentTimeMillis

    def init(self, customScript, configurationAttributes):

        print "Forgot Password - Initialized successfully"
        return True   

    def destroy(self, configurationAttributes):
        print "Forgot Password - Destroyed successfully"
        return True

    def getApiVersion(self):
        # I'm not sure why is 11 and not 2
        return 11

    def getAuthenticationMethodClaims(self, requestParameters):
        return None

    def isValidAuthenticationMethod(self, usageType, configurationAttributes):
        return True

    def getAlternativeAuthenticationMethod(self, usageType, configurationAttributes):
        return None

    def authenticate(self, configurationAttributes, requestParameters, step):
        '''
        Authenticates user
        returns: boolean
        '''
        print "Forgot Password - Authenticate for step %s" % (step)

        identity = CdiUtil.bean(Identity)
        credentials = identity.getCredentials()
        user_name = credentials.getUsername()
        user_password = credentials.getPassword()

        if step == 1:
            authenticationService = CdiUtil.bean(AuthenticationService)
            logged_in = authenticationService.authenticate(user_name, user_password)
            
            if not logged_in:
                email = ServerUtil.getFirstValue(requestParameters, "ForgotPasswordForm:useremail")
                validator = EmailValidator()
                if not validator.check(email):
                    print "Forgot Password - Email format invalid"
                    return False
                else:
                    identity.setWorkingParameter("useremail",email)
                    
                    # Just trying to get the user by the email
                    user_service = CdiUtil.bean(UserService)
                    user2 = user_service.getUserByAttribute("mail", email)

                    if user2 is not None:
                        print "Forgot Password - User with e-mail %s found." % user2.getAttribute("mail")
                    
                        # send email
                        new_token = Token()
                        token = new_token.generateToken()                
                        sender = EmailSender()
                        sender.sendEmail(email,token)
                    
                        identity.setWorkingParameter("token", token)                        
                    else:
                        print "Forgot Password - User with e-mail %s not found" % email

                    return True

            else:
                # if user is already authenticated, returns true.
                user = authenticationService.getAuthenticatedUser()
                print "Forgot Password - User %s is authenticated" % user.getUserId()
                return True

        if step == 2:
            # step 2 user enters token
            credentials = identity.getCredentials()
            user_name = credentials.getUsername()
            user_password = credentials.getPassword()
            
            authenticationService = CdiUtil.bean(AuthenticationService)
            logged_in = authenticationService.authenticate(user_name, user_password)

            # retrieves token typed by user
            input_token = ServerUtil.getFirstValue(requestParameters, "ResetTokenForm:inputToken")

            print "Forgot Password - Token entered by user is %s" % input_token

            token = identity.getWorkingParameter("token")
            print "Forgot Password - Retrieved token"
            email = identity.getWorkingParameter("useremail")
            print "Forgot Password - Retrieved email" 

            # compares token sent and token entered by user
            if input_token == token:
                print "Forgot Password - token entered correctly"
                identity.setWorkingParameter("token_valid", True)
                
                return True
            else:
                print "Forgot Password - wrong token"
                return False
        
        if step == 3:
            # step 3 enters new password (only runs if custom attibute is forgot_password

            user_service = CdiUtil.bean(UserService)
            email = identity.getWorkingParameter("useremail")
            user2 = user_service.getUserByAttribute("mail", email)
            user_name = user2.getUserId()
            new_password = ServerUtil.getFirstValue(requestParameters, "UpdatePasswordForm:newPassword")
            
            print "Forgot Password - New password submited"
        
            # update user info with new password
            user2.setAttribute("userPassword",new_password)
            user_service.updateUser(user2)
            authenticationService2 = CdiUtil.bean(AuthenticationService)
            login = authenticationService2.authenticate(user_name, new_password)

            print "Forgot Password - User updated with new password successfully"

            # update external user password
            self.updateExternalUserPassword(configurationAttributes, user_name, new_password)
            
            return True

    def prepareForStep(self, configurationAttributes, requestParameters, step):
        print "Forgot Password - Preparing for step %s" % step
        return True

    # Return value is a java.util.List<String> 
    def getExtraParametersForStep(self, configurationAttributes, step):
        return Arrays.asList("token","useremail","token_valid")

    # This method determines how many steps the authentication flow may have
    # It doesn't have to be a constant value
    def getCountAuthenticationSteps(self, configurationAttributes):
        return 3

    # The xhtml page to render upon each step of the flow
    # returns a string relative to oxAuth webapp root
    def getPageForStep(self, configurationAttributes, step):
        if step == 1:
            return "/auth/forgot_password/forgot.xhtml"

        if step == 2:
            return "/auth/forgot_password/entertoken.xhtml"

        if step == 3:
            return "/auth/forgot_password/newpassword.xhtml"
    
    def getNextStep(self, configurationAttributes, requestParameters, step):
        # Method used on version 2 (11?)
        return -1
    
    def getLogoutExternalUrl(self, configurationAttributes, requestParameters):
        print "Forgot Password - Get external logout URL call"
        return None
        
    def logout(self, configurationAttributes, requestParameters):
        return True
    
    # code to update password for external user
    def updateExternalUserPassword(self, configurationAttributes, user_id, new_password):
        if configurationAttributes.containsKey('EXTERNAL_LDAP'):
            exLdapFile = configurationAttributes.get('EXTERNAL_LDAP').getValue2()
            exLdap = self.loadAuthConfiguration(exLdapFile)
            print("Forgot Password - retrieve external ldap config: ", exLdap)
            ldaps_url = exLdap["ldaps_url"]
            bind_dn = exLdap["bind_dn"]
            bind_password = CdiUtil.bean(EncryptionService).decrypt(exLdap["bind_password"])
            base_dn = exLdap["base_dn"]
            search_attribute = exLdap["primary_key"]

            env = Hashtable()
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
            env.put(Context.PROVIDER_URL, ldaps_url)
            env.put(Context.SECURITY_PRINCIPAL, bind_dn)
            env.put(Context.SECURITY_CREDENTIALS, bind_password)

            try:
                # Create the initial directory context
                ctx = InitialDirContext(env)
                print("Forgot Password - Connected successfully to LDAP server")

                # Set up search controls
                search_controls = SearchControls()
                search_controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
                search_controls.setReturningAttributes(None)

                search_filter = "({}={})".format(search_attribute, user_id)

                # Attempt to find the user at External LDAP
                try:
                    results = ctx.search(base_dn, search_filter, search_controls)
                    if results is not None:
                        user_dn = results.next().getNameInNamespace()
                        print("Forgot Password - User found: ", user_dn)
                        
                        # Create a ModificationItem for the password change
                        mod_item = ModificationItem(
                            InitialDirContext.REPLACE_ATTRIBUTE,
                            BasicAttribute("userPassword", new_password)
                        )
                        # Perform the password update
                        ctx.modifyAttributes(user_dn, [mod_item])
                        print("Forgot Password - External user password updated successfully for ", user_dn)
                    else:
                        print("Forgot Password - User not found: ", user_id)
                except NameNotFoundException:
                    print("Forgot Password - Please check if the user DN is correct and exists in the LDAP directory.")
            except Exception as e:
                print("Forgot Password - An unexpected error occurred: ", e)
            finally:
                if 'ctx' in locals():
                    ctx.close()
        else:
            print("Forgot Password: No external LDAP config found")
        return True

    def loadAuthConfiguration(self, authConfigurationFile):
        authConfiguration = None

        # Load authentication configuration from file
        f = open(authConfigurationFile, 'r')
        try:
            authConfiguration = json.loads(f.read())
        except:
            print "Forgot Password - Load auth configuration. Failed to load authentication configuration from file: ", authConfigurationFile
            return None
        finally:
            f.close()
        return authConfiguration

