import re
import os
import urlparse
from authlib.common.security import generate_token

from tornado.escape import xhtml_escape
from tornado import template
from DIRAC import rootPath, gLogger

from DIRAC.Core.Web import Conf
from DIRAC.Core.Web.WebHandler import WebHandler, WErr


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
  
  def web_loginComplete(self):
    print('------ web_loginComplete --------')
    # TODO: create here session "state" 
    print(self.request.arguments)
    print(self.request.headers)
    # print(self.request.hash)
    # fetch token with code
    # store session:

    data = self.getSessionData()
    code = self.get_argument('code')
    state = self.get_argument('state')
    result = self.application.parseAuthResponse(self.request, state)
    if not result['OK']:
      raise WErr(503, result['Message'])
    username, userProfile = result['Value']

    session = self.application.getSession(state)

    sessionID = generate_token(30)
    self.application.addSession(sessionID, **dict(session))
    self.set_cookie('session_id', sessionID, httpsOnly=True)
    # self.redirect(session.get('next', '/'))

    t = template.Template('''<!DOCTYPE html>
      <html>
        <head>
          <title>Authentication</title>
          <meta charset="utf-8" />
        </head>
        <body>
          <script type="text/javascript" src="{{base_url}}/static/core/js/utils/oidc/oidc-client.min.js"></script>
          <script>
            new Oidc.UserManager({response_mode: "query"}).signinRedirectCallback().then(function () {
              window.location = {{next}};
            }).catch(function (e) { console.error(e); });
          </script>
        </body>
      </html>''')
    self.finish(t.generate(base_url=data['baseURL'], next=session.get('next', data['baseURL'])))
    self.application.removeSession(session)

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
