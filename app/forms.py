from django import forms
from .models import IP,ShellType
from django.core.exceptions import ValidationError

class CreateForm(forms.ModelForm):
	ipaddress = forms.GenericIPAddressField(
		required=False,
		widget=forms.widgets.TextInput(
            attrs={
                "class":"form-control",
                "placeholder":"IP",
                
            }
        ),
        label="",
    )
	port = forms.IntegerField(required=False,
		widget=forms.widgets.TextInput(
            attrs={
                "class":"form-control",
                "placeholder": "PORT",
               
            }
        ),
        label="",)

	class Meta:
		model = IP
		fields = ['ipaddress','port']


	def clean_port(self, *args, **kwargs):
	    port = self.cleaned_data.get('port')

	    if len(str(port)) < 2:
	        raise forms.ValidationError('Invalid port')

	    if len(str(port)) > 5:
	        raise forms.ValidationError('Invalid port')    

	    return port

