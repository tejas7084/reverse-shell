from django.db import models

class IP(models.Model):
	ipaddress = models.GenericIPAddressField(default='10.10.10.10', blank=True,null=True)
	port = models.IntegerField(default='1234', blank=False,null=True)
	exp_date = models.DateTimeField(db_index=True, auto_now_add=True)
    



	def __str__(self):
		return str(self.ipaddress) + ':' + str(self.port)



class ReverseShell(models.Model):
	name = models.CharField(max_length=9)
	shell = models.CharField(max_length=100)



class ShellType(models.Model):
	name = models.CharField(max_length=50)
	shell_type = models.CharField(max_length=50)
