from rest_framework import serializers
from .models import *


class SchoolSerializer(serializers.ModelSerializer):
    class Meta:
        model = School
        fields = '__all__'

class StudentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Student
        fields = '__all__'

# jwt user authentication serializer

class LoginSerializer(serializers.Serializer):
  username = serializers.CharField(max_length=100)
  password = serializers.CharField(max_length=8)

  class Meta:
        fields = ['email', 'password', 'username']
