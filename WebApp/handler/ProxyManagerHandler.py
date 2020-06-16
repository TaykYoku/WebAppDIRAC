import json
from DIRAC import gConfig, gLogger
from DIRAC.Core.Utilities import Time
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import ProxyManagerClient
from DIRAC.Core.Utilities.List import uniqueElements

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen


class ProxyManagerHandler(WebHandler):

  AUTH_PROPS = "authenticated"

  @asyncGen
  def web_getSelectionData(self):
    callback = {}

    user = self.getUserName()
    if user in ["Anonymous", "anonymous"]:
      self.finish({"success": "false", "error": "You are not authorize to access these data"})

    if len(self.request.arguments) > 0:
      tmp = {}
      for i in self.request.arguments:
        tmp[i] = str(self.request.arguments[i])
      callback["extra"] = tmp
    result = yield self.threadTask(ProxyManagerClient().getUploadedProxiesDetails)  # pylint: disable=no-member
    if not result["OK"]:
      self.finish({"success": "false", "error": result["Message"]})
    data = result["Value"]
    users = []
    groups = []
    for record in data["Dictionaries"]:
      users.append(record['user'])
      groups += record['groups']
    users = uniqueElements(users)
    groups = uniqueElements(groups)
    users.sort()
    groups.sort()
    users = map(lambda x: [x], users)
    groups = map(lambda x: [x], groups)

    callback["username"] = users
    callback["usergroup"] = groups
    result = gConfig.getOption("/WebApp/ProxyManagementMonitoring/TimeSpan", "86400,432000,604800,2592000")
    if result["OK"]:
      tmp = result["Value"]
      tmp = tmp.split(", ")
      if len(tmp) > 0:
        timespan = []
        for i in tmp:
          human_readable = self.__humanize_time(i)
          timespan.append([i, human_readable])
      else:
        timespan = [["Nothing to display"]]
    else:
      timespan = [["Error during RPC call"]]
    callback["expiredBefore"] = timespan
    callback["expiredAfter"] = timespan
    self.finish(callback)

  @asyncGen
  def web_getProxyManagerData(self):
    callback = {}

    user = self.getUserName()
    if user in ["Anonymous", "anonymous"]:
      self.finish({"success": "false", "error": "You are not authorize to access these data"})
    start, limit, sort, req = self.__request()
    # pylint: disable=no-member
    result = yield self.threadTask(ProxyManagerClient().getDBContents, req, start, limit)
    gLogger.info("*!*!*!  RESULT: \n%s" % result)
    if not result['OK']:
      self.finish({"success": "false", "error": result["Message"]})
    svcData = result['Value']
    proxies = []
    for record in svcData['Dictionaries']:
      proxies.append({'proxyid': "%s@%s" % (record["DN"],
                                            record['groups'] if record['groups'] > 1 else record['groups'][0]),
                      'UserName': record['user'],
                      'UserDN': record['DN'],
                      'UserGroups': record['groups'],
                      'ExpirationTime': str(record['expirationtime']),
                      'Provider': record['provider'],
                      'ProxyProvider': record['provider']})
    timestamp = Time.dateTime().strftime("%Y-%m-%d %H:%M [UTC]")
    data = {"success": "true", "result": proxies, "total": svcData['TotalRecords'], "date": timestamp}
    self.finish(data)

  @asyncGen
  def web_deleteProxies(self):

    try:
      webIds = list(json.loads(self.request.arguments['idList'][-1]))
    except BaseException:
      self.finish({"success": "false", "error": "No valid id's specified"})
    idList = []
    for id in webIds:
      spl = id.split("@")
      dn = "@".join(spl[:-1])
      group = spl[-1]
      idList.append((dn, group))
    retVal = yield self.threadTask(ProxyManagerClient().deleteProxy, None, None, idList)  # pylint: disable=no-member
    callback = {}
    if retVal['OK']:
      callback = {"success": "true", "result": retVal['Value']}
    else:
      callback = {"success": "false", "error": retVal['Message']}
    self.finish(callback)

  def __humanize_time(self, sec=False):
    """
    Converts number of seconds to human readble values. Max return value is
    "More then a year" year and min value is "One day"
    """
    if not sec:
      return "Time span is not specified"
    try:
      sec = int(sec)
    except BaseException:
      return "Value from CS is not integer"
    month, week = divmod(sec, 2592000)
    if month > 0:
      if month > 12:
        return "More then a year"
      elif month > 1:
        return str(month) + " months"
      else:
        return "One month"
    week, day = divmod(sec, 604800)
    if week > 0:
      if week == 1:
        return "One week"
      else:
        return str(week) + " weeks"
    day, hours = divmod(sec, 86400)
    if day > 0:
      if day == 1:
        return "One day"
      else:
        return str(day) + " days"

  def __request(self):
    gLogger.info("!!!  PARAMS: ", str(self.request.arguments))
    req = {}

    start = 0
    limit = 25

    if "limit" in self.request.arguments and len(self.request.arguments["limit"][0]) > 0:
      limit = int(self.request.arguments["limit"][0])

    if "start" in self.request.arguments and len(self.request.arguments["start"][0]) > 0:
      start = int(self.request.arguments["start"][0])

    try:
      sortDirection = str(self.request.arguments['sortDirection']).strip()
    except BaseException:
      sortDirection = "ASC"
    try:
      sortField = str(self.request.arguments['sortField']).strip()
    except BaseException:
      sortField = "UserName"
    sort = [[sortField, sortDirection]]
    gLogger.info("!!!  S O R T : ", sort)

    if "username" in self.request.arguments:
      users = list(json.loads(self.request.arguments['username'][-1]))
      if len(users) > 0:
        req['UserName'] = users

    if "usergroup" in self.request.arguments:
      usersgroup = list(json.loads(self.request.arguments['usergroup'][-1]))
      if len(usersgroup) > 0:
        req['UserGroups'] = usersgroup

    if "usersgroup" in self.request.arguments and len(self.request.arguments["persistent"]) > 0:
      if str(self.request.arguments["persistent"]) in ["True", "False"]:
        req["PersistentFlag"] = str(self.request.arguments["persistent"])
    before = False
    after = False
    if "expiredBefore" in self.request.arguments and len(self.request.arguments["expiredBefore"]) > 0:
      try:
        before = int(self.request.arguments["expiredBefore"])
      except BaseException:
        pass
    if "expiredAfter" in self.request.arguments and len(self.request.arguments["expiredAfter"]) > 0:
      try:
        after = int(self.request.arguments["expiredAfter"])
      except BaseException:
        pass
    if before and after:
      if before > after:
        req["beforeDate"] = before
        req["afterDate"] = after
    else:
      if before:
        req["beforeDate"] = before
      if after:
        req["afterDate"] = after
    gLogger.always("REQUEST:", req)
    return (start, limit, sort, req)
