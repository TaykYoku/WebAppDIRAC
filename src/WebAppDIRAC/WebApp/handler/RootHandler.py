import re
import os
from six.moves import urllib_parse as urlparse

from tornado.escape import xhtml_escape
from tornado import template

from DIRAC import rootPath, gLogger, S_OK, gConfig

from WebAppDIRAC.Lib import Conf
from WebAppDIRAC.Lib.WebHandler import _WebHandler as WebHandler, WErr, asyncGen
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
from DIRAC.ConfigurationSystem.Client.Utilities import getWebClient, getAuthorisationServerMetadata
from DIRAC.FrameworkSystem.private.authorization.utils.Tokens import OAuth2Token


class RootHandler(WebHandler):

  AUTH_PROPS = "all"
  LOCATION = "/"

  def web_changeGroup(self):
    to = self.get_argument("to")
    self.__change(group=to)

  def web_changeSetup(self):
    to = self.get_argument("to")
    self.__change(setup=to)

  def __change(self, setup=None, group=None):
    if not setup:
      setup = self.getUserSetup()
    if not group:
      group = self.getUserGroup() or 'anon'
    qs = False
    if 'Referer' in self.request.headers:
      o = urlparse.urlparse(self.request.headers['Referer'])
      qs = '/?%s' % o.query
    url = [Conf.rootURL().strip("/"), "s:%s" % setup, "g:%s" % group]
    self.redirect("/%s%s" % ("/".join(url), qs))

  def web_getConfigData(self):
    return self.getSessionData()

  def web_logout(self):
    """ Start authorization flow
    """
    token = self.get_secure_cookie('session_id')
    if token:
      token = json.loads(token)
      if token.get('refresh_token'):
        OAuth2IdProvider(**self._clientConfig).revokeToken(token['refresh_token'])
    self.clear_cookie('session_id')
    self.set_cookie('authGrant', 'Visitor')
    self.redirect('/DIRAC')

  def web_login(self):
    """ Start authorization flow
    """
    provider = self.get_argument('provider')

    authClient = OAuth2IdProvider(**self._clientConfig)
    authClient.store_token = self._storeToken

    # Create PKCE things
    code_verifier = generate_token(48)
    code_challenge = create_s256_code_challenge(code_verifier)
    url = authClient.metadata['authorization_endpoint']
    if provider:
      url += '/%s' % provider
    uri, state = authClient.create_authorization_url(url, code_challenge=code_challenge,
                                                     code_challenge_method='S256')
    authSession = {'state': state, 'code_verifier': code_verifier, 'provider': provider,
                   'next': self.get_argument('next', '/DIRAC')}
    self.set_secure_cookie('webauth_session', json.dumps(authSession), secure=True, httponly=True)
    self.set_cookie('authGrant', 'Visitor')
    # Redirect to authorization server
    self.redirect(uri)

  def web_loginComplete(self):
    """ Finishing authoriation flow
    """
    code = self.get_argument('code')
    state = self.get_argument('state')

    authClient = OAuth2IdProvider(**self._clientConfig)

    # Parse response
    authSession = json.loads(self.get_secure_cookie('webauth_session'))

    authClient.fetch_access_token(authClient.metadata['token_endpoint'],
                                  authorization_response=self.request.uri,
                                  code_verifier=authSession.get('code_verifier'))
    
    # result = authClient.parseAuthResponse(self.request, authSession)
    self.clear_cookie('webauth_session')


    token = OAuth2Token(authClient.token)
    # Create session to work through portal
    self.set_secure_cookie('session_id', json.dumps(dict(token)), secure=True, httponly=True)
    self.set_cookie('authGrant', 'Session')

    group = token.groups[0]
    url = '/'.join([Conf.rootURL().strip("/"), "s:%s" % self.getUserSetup(), "g:%s" % group])
    nextURL = "/%s/?%s" % (url, urlparse.urlparse(authSession['next']).query)
    # Save token and go to main page
    # with document('DIRAC authentication') as html:
    #   dom.div('Authorization is done.',
    #           style='display:flex;justify-content:center;align-items:center;padding:28px;font-size:28px;')
    #   dom.script("sessionStorage.setItem('access_token','%s');window.location='%s'" % (access_token, nextURL),
    #              type="text/javascript")
    # return template.Template(html.render()).generate()
    t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authentication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          Authorization is done.
          <script>
            sessionStorage.setItem("access_token", "{{access_token}}");
            window.location = "{{next}}";
          </script>
        </body>
      </html>''')
    return t.generate(next=nextURL, access_token=token.access_token)

  def web_index(self):
    # Render base template
    data = self.getSessionData()

    url_state = ""
    if "url_state" in self.request.arguments and len(self.get_argument("url_state")) > 0:
      url_state = xhtml_escape(self.get_argument("url_state"))

    # Default theme/view settings
    theme_name = "crisp"
    view_name = Conf.getTheme()
    if ":" in view_name:
      view_name, theme_name = view_name.split(":", 1)

    # User selected theme/view
    if "view" in self.request.arguments and len(self.get_argument("view")) > 0:
      view_name = xhtml_escape(self.get_argument("view"))

    if "theme" in self.request.arguments and len(self.get_argument("theme")) > 0:
      theme_name = xhtml_escape(self.get_argument("theme").lower())

    open_app = ""
    if "open_app" in self.request.arguments and len(self.get_argument("open_app")) > 0:
      open_app = xhtml_escape(self.get_argument("open_app").strip())

    icon = data['baseURL'] + Conf.getIcon()
    background = data['baseURL'] + Conf.getBackgroud()
    logo = data['baseURL'] + Conf.getLogo()
    welcomeFile = Conf.getWelcome()
    welcome = ''
    if welcomeFile:
      try:
        with open(welcomeFile, 'r') as f:
          welcome = f.read().replace('\n', '')
      except BaseException:
        gLogger.warn('Welcome page not found here: %s' % welcomeFile)

    level = str(gLogger.getLevel()).lower()
    self.render("root.tpl", iconUrl=icon, base_url=data['baseURL'], _dev=Conf.devMode(),
                ext_version=data['extVersion'], url_state=url_state,
                extensions=data['extensions'], auth_client_settings=data['configuration']['AuthorizationClient'],
                credentials=data['user'], title=Conf.getTitle(),
                theme=theme_name, root_url=Conf.rootURL(), view=view_name,
                open_app=open_app, debug_level=level, welcome=welcome,
                backgroundImage=background, logo=logo, bugReportURL=Conf.bugReportURL(),
                http_port=Conf.HTTPPort(), https_port=Conf.HTTPSPort())
