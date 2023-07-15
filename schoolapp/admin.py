from django.contrib import admin
from .models import Student, School, NewUser, Document

admin.site.register(School)
admin.site.register(Student)
admin.site.register(NewUser)
admin.site.register(Document)