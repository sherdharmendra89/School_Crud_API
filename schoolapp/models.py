from django.db import models

class School(models.Model):
    name = models.CharField(max_length=100)
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)

class Student(models.Model):
    name = models.CharField(max_length=100)
    enrollment = models.CharField(max_length=13, unique=True)
    school = models.ForeignKey(School, on_delete=models.CASCADE)
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)


# other 


class NewUser(models.Model):
    GENDER_CHOICES = (
        ('M', 'Male'),
        ('F', 'Female'),
        ('O', 'Other'),
    )
    # INTEREST_CHOICES = [
    #     ('sports', 'Sports'),
    #     ('music', 'Music'),
    #     ('books', 'Books'),
    # ]

    name = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    email = models.EmailField()
    city = models.CharField(max_length=255)
    state = models.CharField(max_length=255)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES)
    
    interests = models.CharField(max_length=255, blank=True, null=True)
    documents = models.ManyToManyField('Document')

    def __str__(self):
        return self.name

class Document(models.Model):
    user = models.ForeignKey(NewUser, on_delete=models.CASCADE)
    document = models.FileField(upload_to='documents/')
    docname = models.CharField(max_length=255, default="test")


    def __str__(self):
        return str(self.document)

