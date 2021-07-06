import re
import os
import json
import pprint
from dominate import document, tags as dom
from six.moves import urllib_parse as urlparse

from tornado.escape import xhtml_escape
from tornado import template

from DIRAC import rootPath, gLogger, S_OK, gConfig

from WebAppDIRAC.Lib import Conf
from WebAppDIRAC.Lib.WebHandler import _WebHandler as WebHandler, WErr, asyncGen


class RootHandler(WebHandler):

  AUTH_PROPS = "all"
  LOCATION = "/"

  def web_changeGroup(self):
    return self.__change(group=self.get_argument("to"))

  def finish_changeGroup(self):
    self.redirect(self.result)

  def web_changeSetup(self):
    return self.__change(setup=self.get_argument("to"))

  def finish_changeSetup(self):
    self.redirect(self.result)

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
    return "/%s%s" % ("/".join(url), qs)

  def web_getConfigData(self):
    return self.getSessionData()

  def web_logout(self):
    """ Start authorization flow
    """
    token = self.get_secure_cookie('session_id')
    if token:
      token = json.loads(token)
      if token.get('refresh_token'):
        result = self._idps.getIdProvider('DIRACWeb')
        if result['OK']:
          cli = result['Value']
          cli.token = token
          cli.revokeToken(token['refresh_token'])

  def finish_logout(self):
    self.clear_cookie('session_id')
    self.set_cookie('authGrant', 'Visitor')
    self.redirect('/DIRAC')

  def web_login(self):
    """ Start authorization flow
    """
    result = self._idps.getIdProvider('DIRACWeb')
    if not result['OK']:
      raise WErr(500, result['Message'])
    cli = result['Value']
    provider = self.get_argument('provider')
    if provider:
      cli.metadata['authorization_endpoint'] = '%s/%s' % (cli.get_metadata('authorization_endpoint'), provider)
    return cli.submitNewSession()

  def finish_login(self):
    uri, state, session = self.result

    # Save authorisation session
    session.update(dict(state=state, provider=self.get_argument('provider'), next=self.get_argument('next', '/DIRAC')))
    self.set_secure_cookie('webauth_session', json.dumps(session), secure=True, httponly=True)

    # Redirect to authorization server
    self.set_cookie('authGrant', 'Visitor')
    self.redirect(uri)

  def web_loginComplete(self):
    """ Finishing authoriation flow
    """
    code = self.get_argument('code')
    state = self.get_argument('state')

    result = self._idps.getIdProvider('DIRACWeb')
    if not result['OK']:
      return result
    cli = result['Value']

    # Parse response
    authSession = json.loads(self.get_secure_cookie('webauth_session'))

    result = cli.fetchToken(authorization_response=self.request.uri, code_verifier=authSession.get('code_verifier'))
    if not result['OK']:
      return result
    token = result['Value']

    # Remove authorisation session.
    self.clear_cookie('webauth_session')

    # Create session to work through portal
    self.log.debug('Tokens received:\n', pprint.pformat(token))
    self.set_secure_cookie('session_id', json.dumps(dict(token)), secure=True, httponly=True)
    self.set_cookie('authGrant', 'Session')

    result = cli.researchGroup()
    if not result['OK']:
      return result
    group = result['Value'].get('group')

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
    return t.generate(next=nextURL, access_token=token['access_token'])

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

    welcome = ''
    welcomeFile = Conf.getWelcome()
    if welcomeFile:
      try:
        with open(welcomeFile, 'r') as f:
          welcome = f.read().replace('\n', '')
      except BaseException:
        gLogger.warn('Welcome page not found here: %s' % welcomeFile)

    return dict(_dev=Conf.devMode(),
                logo=data['baseURL'] + Conf.getLogo(),
                view=view_name,
                theme=theme_name,
                title=Conf.getTitle(),
                welcome=welcome,
                iconUrl=data['baseURL'] + Conf.getIcon(),
                open_app=open_app,
                base_url=data['baseURL'],
                root_url=Conf.rootURL(),
                url_state=url_state,
                http_port=Conf.HTTPPort(),
                https_port=Conf.HTTPSPort(),
                extensions=data['extensions'],
                credentials=data['user'],
                ext_version=data['extVersion'],
                debug_level=str(gLogger.getLevel()).lower(),
                bugReportURL=Conf.bugReportURL(),
                backgroundImage=data['baseURL'] + Conf.getBackgroud(),
                auth_client_settings=data['configuration'].get('AuthorizationClient', {}))

  def finish_index(self):
    self.render("root.tpl", **self.result)
