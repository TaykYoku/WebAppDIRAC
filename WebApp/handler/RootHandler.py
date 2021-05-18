import re
import os
import json
import urlparse
from dominate import document, tags as dom
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from tornado.escape import xhtml_escape
from tornado import template

from DIRAC import rootPath, gLogger, S_OK, gConfig

from WebAppDIRAC.Lib import Conf
from WebAppDIRAC.Lib.WebHandler import _WebHandler as WebHandler, WErr, asyncGen
from DIRAC.Resources.IdProvider.OAuth2IdProvider import OAuth2IdProvider
from DIRAC.FrameworkSystem.private.authorization.utils.Tokens import OAuth2Token


class RootHandler(WebHandler):

  AUTH_PROPS = "all"
  LOCATION = "/"

  def web_changeGroup(self):
    try:
      to = self.request.arguments['to'][-1]
    except KeyError:
      raise WErr(400, "Missing 'to' argument")
    # Not for now, too many requests to AS
    # tokens = self.getRemoteCredentials()['Tokens']
    # token = self._authClient.exchange_token(self._authClient.metadata['token_endpoint'],
    #                                         refresh_token=tokens.refresh_token,
    #                                         access_token=tokens.access_token,
    #                                         scope='g:%s' % to)
    # self.set_secure_cookie('session_id', json.dumps(dict(token)), secure=True, httponly=True)
    self.__change(group=to)

  def web_changeSetup(self):
    try:
      to = self.request.arguments['to'][-1]
    except KeyError:
      raise WErr(400, "Missing 'to' argument")
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
        cli = self._idps.getIdProvider('WebAppDIRAC')
        cli.token = token
        cli.revokeToken(token['refresh_token'])
    self.clear_cookie('session_id')
    self.set_cookie('authGrant', 'Visitor')
    self.redirect('/DIRAC')

  def web_login(self):
    """ Start authorization flow
    """
    cli = self._idps.getIdProvider('WebAppDIRAC')
    provider = self.get_argument('provider')
    if provider:
      cli.metadata['authorization_endpoint'] += '/%s' % provider
    uri, state, seesion = cli.submitNewSession()

    # Save authorisation session
    session.update(dict(state=state, provider=provider, next=self.get_argument('next', '/DIRAC')))
    self.set_secure_cookie('webauth_session', json.dumps(session), secure=True, httponly=True)

    # Redirect to authorization server
    self.set_cookie('authGrant', 'Visitor')
    self.redirect(uri)

  def web_loginComplete(self):
    """ Finishing authoriation flow
    """
    code = self.get_argument('code')
    state = self.get_argument('state')

    cli = self._idps.getIdProvider('WebAppDIRAC')

    # Parse response
    authSession = json.loads(self.get_secure_cookie('webauth_session'))

    token = cli.fetchToken(authorization_response=self.request.uri, code_verifier=authSession.get('code_verifier')))
    
    # Remove authorisation session
    self.clear_cookie('webauth_session')

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
    if "url_state" in self.request.arguments and len(self.request.arguments["url_state"][0]) > 0:
      url_state = xhtml_escape(self.request.arguments["url_state"][0])

    # Default theme/view settings
    theme_name = "crisp"
    view_name = Conf.getTheme()
    if ":" in view_name:
      view_name, theme_name = view_name.split(":", 1)

    # User selected theme/view
    if "view" in self.request.arguments and len(self.request.arguments["view"][0]) > 0:
      view_name = xhtml_escape(self.request.arguments["view"][0])

    if "theme" in self.request.arguments and len(self.request.arguments["theme"][0]) > 0:
      theme_name = xhtml_escape(self.request.arguments["theme"][0].lower())

    open_app = ""
    if "open_app" in self.request.arguments and len(self.request.arguments["open_app"][0]) > 0:
      open_app = xhtml_escape(self.request.arguments["open_app"][0].strip())

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
