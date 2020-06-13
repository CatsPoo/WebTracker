from datetime import date
from datetime import datetime
from xlwt import Workbook 

class Report:

	def __init__(self):
		self.row=1
		self.wb = Workbook()
		self.current_date = date.today().strftime("%d_%m_%Y")
		self.report  = self.wb.add_sheet(self.current_date) 

		self.report.write(0,0,"time")
		self.report.write(0,1,"address")

		self.save()
	
	def add_row(self,src,dest):
		current_time = datetime.now().strftime("%H:%M:%S")
		self.report.write(self.row,0, current_time )
		self.report.write(self.row,1, src )
		self.report.write(self.row,2,dest)
		self.row = self.row+1

		self.save()

	def save(self):
		open(("Reports/"+self.current_date+".xls","a")
        self.wb.save("Reports/"+self.current_date+".xls")

