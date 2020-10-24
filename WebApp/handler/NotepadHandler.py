
from DIRAC.Core.Tornado.Web.WebHandler import WebHandler

class NotepadHandler(WebHandler):

  AUTH_PROPS = "authenticated"

  def index(self):
    pass
