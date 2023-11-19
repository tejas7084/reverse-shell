# Generated by Django 4.2.6 on 2023-11-11 13:12

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='IP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ipaddress', models.GenericIPAddressField(blank=True, default='10.10.10.10', null=True)),
                ('port', models.IntegerField(default='1234', null=True)),
                ('exp_date', models.DateTimeField(auto_now_add=True, db_index=True)),
            ],
        ),
        migrations.CreateModel(
            name='ReverseShell',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=9)),
                ('shell', models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name='ShellType',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50)),
                ('shell_type', models.CharField(max_length=50)),
            ],
        ),
    ]