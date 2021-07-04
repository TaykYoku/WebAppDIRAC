from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import base64
import zlib
import json
import six

from DIRAC.Core.Utilities import DEncode
from DIRAC.Core.DISET.ThreadConfig import ThreadConfig
from DIRAC.FrameworkSystem.Client.UserProfileClient import UserProfileClient

from WebAppDIRAC.Lib.WebHandler import _WebHandler as WebHandler, WErr, asyncGen


class UPHandler(WebHandler):
  RAISE_DIRAC_ERROR = True
  AUTH_PROPS = "authenticated"
  __tc = ThreadConfig()

  def _prepare(self):
    super(UPHandler, self)._prepare()
    self.set_header("Pragma", "no-cache")
    self.set_header("Cache-Control", "max-age=0, no-store, no-cache, must-revalidate")
    # Do not use the defined user setup. Use the web one to show the same profile independently of user setup
    self.__tc.setSetup(False)

  def __getUP(self):
    obj = self.get_argument("obj")
    app = self.get_argument("app")
    return UserProfileClient("Web/%s/%s" % (obj, app))

  def web_saveAppState(self):
    up = self.__getUP()
    name = self.get_argument("name")
    state = self.get_argument("state")
    data = base64.b64encode(zlib.compress(DEncode.encode(state), 9))
    # before we save the state (modify the state) we have to remember the actual access: ReadAccess and PublishAccess
    result = up.getVarPermissions(name)
    if result['OK']:
      access = result['Value']
    else:
      access = {'ReadAccess': 'USER', 'PublishAccess': 'USER'}  # this is when the application/desktop does not exists.
    result = up.storeVar(name, data)
    if not result['OK']:
      return result
    # change the access to the application/desktop
    result = up.setVarPermissions(name, access)
    if not result['OK']:
      return result

    return S_OK()

  def web_makePublicAppState(self):
    up = self.__getUP()
    name = self.get_argument("name")
    access = self.get_argument("access", "ALL").upper()
    if access not in ('ALL', 'VO', 'GROUP', 'USER'):
      raise WErr(400, "Invalid access")

    revokeAccess = {'ReadAccess': access}
    if access == 'USER':  # if we make private a state,
      # we have to revoke from the public as well
      revokeAccess['PublishAccess'] = 'USER'

    # TODO: Check access is in either 'ALL', 'VO' or 'GROUP'
    result = up.setVarPermissions(name, revokeAccess)
    if not result['OK']:
      return result
    return S_OK()

  def web_loadAppState(self):
    up = self.__getUP()
    name = self.get_argument("name")
    result = up.retrieveVar(name)
    if not result['OK']:
      return result
    data = result['Value']
    data, count = DEncode.decode(zlib.decompress(base64.b64decode(data)))
    return data

  def web_loadUserAppState(self):
    up = self.__getUP()
    user = self.get_argument("user")
    group = self.get_argument("group")
    name = self.get_argument("name")
    result = up.retrieveVarFromUser(user, group, name)
    if not result['OK']:
      return result
    data = result['Value']
    data, count = DEncode.decode(zlib.decompress(base64.b64decode(data)))
    return data

  auth_listAppState = ['all']

  def web_listAppState(self):
    up = self.__getUP()
    result = up.retrieveAllVars()
    if not result['OK']:
      return result
    data = result['Value']
    for k in data:
      # Unpack data
      data[k] = json.loads(DEncode.decode(zlib.decompress(base64.b64decode(data[k])))[0])
    self.finish(data)

  def web_delAppState(self):
    up = self.__getUP()
    name = self.get_argument("name")
    return up.deleteVar(name)

  auth_listPublicDesktopStates = ['all']

  def web_listPublicDesktopStates(self):
    up = self.__getUP()
    result = up.listAvailableVars()
    if not result['OK']:
      return result
    data = result['Value']
    paramNames = ['UserName', 'Group', 'VO', 'desktop']

    records = [dict(zip(paramNames, i)) for i in data]
    sharedDesktops = {}
    for i in records:
      result = up.getVarPermissions(i['desktop'])
      if not result['OK']:
        return result
      if result['Value']['ReadAccess'] == 'ALL':
        print(i['UserName'], i['Group'], i)
        result = up.retrieveVarFromUser(i['UserName'], i['Group'], i['desktop'])
        if not result['OK']:
          return result
        if i['UserName'] not in sharedDesktops:
          sharedDesktops[i['UserName']] = {}
        sharedDesktops[i['UserName']][i['desktop']] = json.loads(
            DEncode.decode(zlib.decompress(base64.b64decode(result['Value'])))[0])
        sharedDesktops[i['UserName']]['Metadata'] = i
    return sharedDesktops

  def web_makePublicDesktopState(self):
    up = UserProfileClient("Web/application/desktop")
    name = self.get_argument("name")
    access = self.get_argument("access", "ALL").upper()
    if access not in ('ALL', 'VO', 'GROUP', 'USER'):
      raise WErr(400, "Invalid access")
    # TODO: Check access is in either 'ALL', 'VO' or 'GROUP'
    result = up.setVarPermissions(name, {'ReadAccess': access})
    if not result['OK']:
      return result
    return S_OK()

  def web_changeView(self):
    up = self.__getUP()
    desktopName = self.get_argument("desktop")
    view = self.get_argument("view")
    result = up.retrieveVar(desktopName)
    if not result['OK']:
      return result
    data = result['Value']
    oDesktop = json.loads(DEncode.decode(zlib.decompress(base64.b64decode(data)))[0])
    oDesktop[six.text_type('view')] = six.text_type(view)
    oDesktop = json.dumps(oDesktop)
    data = base64.b64encode(zlib.compress(DEncode.encode(oDesktop), 9))
    return up.storeVar(desktopName, data)

  auth_listPublicStates = ['all']

  def web_listPublicStates(self):

    user = self.getUserName()

    up = self.__getUP()
    retVal = up.getUserProfileNames({'PublishAccess': 'ALL'})
    if not retVal['OK']:
      raise WErr.fromSERROR(retVal)
    records = retVal['Value']
    if not records:
      raise WErr(404, "There are no public states!")

    mydesktops = {'name': 'My Desktops',
                  'group': '',
                  'vo': '',
                  'user': '',
                  'iconCls': 'my-desktop',
                  'children': []
                  }
    shareddesktops = {'name': 'Shared Desktops',
                      'group': '',
                      'vo': '',
                      'user': '',
                      'expanded': 'true',
                      'iconCls': 'shared-desktop',
                      'children': []
                      }

    myapplications = {'name': 'My Applications',
                      'group': '',
                      'vo': '',
                      'user': '',
                      'children': []
                      }
    sharedapplications = {'name': 'Shared Applications',
                          'group': '',
                          'vo': '',
                          'user': '',
                          'expanded': 'true',
                          'iconCls': 'shared-desktop',
                          'children': []
                          }

    desktopsApplications = {
        'text': '.', 'children': [{'name': 'Desktops',
                                   'group': '',
                                   'vo': '',
                                   'user': '',
                                   'children': [mydesktops,
                                                shareddesktops]
                                   }, {'name': 'Applications',
                                       'group': '',
                                       'vo': '',
                                       'user': '',
                                       'children': [myapplications,
                                                    sharedapplications]
                                       }
                                  ]
    }
    for record in records:
      permissions = record["permissions"]
      if permissions['PublishAccess'] == 'ALL':
        if record["app"] == 'desktop':
          record['type'] = 'desktop'
          record['leaf'] = 'true'
          record['iconCls'] = 'core-desktop-icon',
          if record['user'] == user:
            mydesktops['children'].append(record)
          else:
            shareddesktops['children'].append(record)
        else:
          record['type'] = 'application'
          record['leaf'] = 'true'
          record['iconCls'] = 'core-application-icon'
          if record['user'] == user:
            myapplications['children'].append(record)
          else:
            sharedapplications['children'].append(record)

    return desktopsApplications

  def web_publishAppState(self):
    up = self.__getUP()
    name = self.get_argument("name")
    access = self.get_argument("access", "ALL").upper()
    if access not in ('ALL', 'VO', 'GROUP', 'USER'):
      raise WErr(400, "Invalid access")

    return up.setVarPermissions(name, {'PublishAccess': access, 'ReadAccess': access})
