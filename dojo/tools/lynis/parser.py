from dojo.models import Finding

class LynisParser(object):
    def __init__(self, output, test):
      self.log_file = output
      self.items = self.parse_log()
      self.test = test

    def parse_log(self):
      warnings = []
      suggestions = []
      findings = []
      if self.log_file is None:
        return None
      else:
        line = self.log_file.readline()

      while line:
        if "Warning" in line:
          warnings.append(line)
        elif "Suggestion" in line:
          suggestions.append(line)
        line = self.log_file.readline()
      findings = self.parse_list(warnings, "Warning", findings)
      findings = self.parse_list(suggestions, "Suggestion", findings)
      return findings

    def parse_list(self, list: list, list_type: str, findings: list):
      severity = "Info"
      date_length = 20
      type_length = 0
      if list_type == "Suggestion":
        type_length = 12
        severity = "Low"
      elif list_type == "Warning":
        type_length = 9
        severity = "High"
        
      for item in list:
        el = item[date_length:(len(item)-1)]
        msg = el[type_length:(el.find("["))-1] #extract warning value
        url = "https://cisofy.com/lynis/controls/" + el[(el.find("[")+6):(el.find("]")-1)] #extract first bracket group
        el = el[(el.find("]")+2):] #remove the first bracket group
        details = el[9:(el.find("]"))] # extract second bracket group (8 is len of 'details:')
        if details == '':
          details = "-"
        solution = el[(el.find("]")+12):(len(el)-1)] #extract third bracket group
        find = Finding()
        find.test=self.test
        find.title=msg
        find.severity=severity
        find.numerical_severity=Finding.get_numerical_severity(severity)
        find.description=details
        find.mitigation=solution
        find.url=url
        find.active=True
        find.verified=True
        find.false_p=False,
        find.duplicate=False,
        find.out_of_scope=False,
        find.mitigated=None,
        find.impact="No impact provided"
        findings.append(find)
      return findings
