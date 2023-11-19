from django.contrib import admin
from .models import IP, ReverseShell, ShellType

admin.site.register(IP)
admin.site.register(ReverseShell)
admin.site.register(ShellType)