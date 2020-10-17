import re
import os
import urlparse
from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge

from tornado.escape import xhtml_escape
from tornado import template

from DIRAC import rootPath, gLogger, S_OK

from DIRAC.Core.Web import Conf
from DIRAC.Core.Web.WebHandler import WebHandler, WErr, asyncGen


class RootHandler(WebHandler):

  AUTH_PROPS = "all"
  LOCATION = "/"

  def web_upload(self):

    if 'filename' not in self.request.arguments:
      raise WErr(400, "Please provide a file name!")
    data = self.request.arguments.get("data", "")[0]
    filename = self.request.arguments.get("filename", "")[0]

    if re.match("(?!\.)^[\w\d_\.\-]*$", filename):
      filepath = "%s/webRoot/www/pilot/%s" % (rootPath, filename)
    else:
      raise WErr(400, "Please provide a valid file name!")

    try:
      tmpfile = "%s.tmp" % filepath
      with open(tmpfile, 'w') as tmp:
        tmp.write(data)
      os.rename(tmpfile, filepath)
    except OSError as e:
      raise WErr(400, "Cannot create the file: %s; %s" % (filename, repr(e)))
    self.finish('File has created')

  def web_changeGroup(self):
    try:
      to = self.request.arguments['to'][-1]
    except KeyError:
      raise WErr(400, "Missing 'to' argument")
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
      qs = '?%s' % o.query
    url = [Conf.rootURL().strip("/"), "s:%s" % setup, "g:%s" % group]
    self.redirect("/%s%s" % ("/".join(url), qs))

  def web_getConfigData(self):
    self.finish(self.getSessionData())

  @asyncGen
  def web_fetchToken(self):
    """ Fetch access token
    """
    print('------ web_fetchToken --------')
    sessionID = self.getCurrentSession()
    if self.application.getSession(sessionID)['access_token'] != self.get_argument('access_token'):
      self.set_status(401)
      self.finish('Unauthorize.')
      return

    # Create PKCE things
    url = self.application._authClient.metadata['token_endpoint']
    token = self.application._authClient.refresh_token(url, refresh_token=session['refresh_token'],
                                                       scope='%s changeGroup' % self.getUserGroup())
    self.application.updateSession(sessionID, **token)

    self.finish(token['access_token'])

  @asyncGen
  def web_login(self):
    """ Start authorization flow
    """
    print('------ web_login --------')
    provider = self.get_argument('provider')

    # Create PKCE things
    code_verifier = generate_token(48)
    code_challenge = create_s256_code_challenge(code_verifier)
    url = self.application._authClient.metadata['authorization_endpoint']
    if provider:
      url += '/%s' % provider
    uri, state = self.application._authClient.create_authorization_url(url, code_challenge=code_challenge,
                                                                       code_challenge_method='S256',
                                                                       scope='changeGroup')
    self.application.addSession(state, code_verifier=code_verifier, provider=provider,
                                next=self.get_argument('next', '/DIRAC'))
    
    # Redirect to authorization server
    self.redirect(uri)

  @asyncGen
  def web_loginComplete(self):
    """ Finishing authoriation flow
    """
    print('------ web_loginComplete --------')
    code = self.get_argument('code')
    state = self.get_argument('state')

    # Parse response
    self.application._authClient.store_token = None
    result = yield self.threadTask(self.application._authClient.parseAuthResponse, self.request,
                                   self.application.getSession(state))

    self.application.removeSession(state)
    if not result['OK']:
      self.finish(result['Message'])
      return
    # FINISHING with IdP auth result
    username, userProfile, session = result['Value']

    # Create session to work through portal
    self.application.addSession(dict(session.update(id=generate_token(30))))
    self.set_secure_cookie('session_id', session.id, secure=True, httponly=True)

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
    self.finish(t.generate(next=session['next'], access_token=session['access_token']))

  def web_index(self):
    print('=== index ===')
    print(self.request.arguments)
    print(self.request.headers)
    print('=============')
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
